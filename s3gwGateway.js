const LOGGABLE_METHODS = new Set(["PUT", "DELETE", "POST", "GET", "HEAD"]);

const LOGGABLE_POST_ACTIONS = new Set([
    "completeMultipartUpload",
    "createMultipartUpload",
    "restoreObject",
    "deleteObjects",
    "createPresignedUrl",
]);

const kvCache = new Map();
const CACHE_TTL_MS = 60000;
const NEGATIVE_CACHE_TTL_MS = 5000;
const MAX_KV_CACHE_ENTRIES = 1000;

const signingKeyCache = new Map();
const SIGNING_KEY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SIGNING_KEY_CACHE_ENTRIES = 500;

const tokenCryptoKeyCache = new Map();
const MAX_TOKEN_KEY_CACHE_ENTRIES = 500;

const consumedTokenCache = new Map();
const MAX_CONSUMED_TOKEN_CACHE_ENTRIES = 2000;

const dlpMemoryCounters = new Map();
const MAX_DLP_COUNTER_ENTRIES = 2000;

const MAX_SIGV4_CLOCK_SKEW_MS = 15 * 60 * 1000;
const DEFAULT_PRESIGN_TTL_SECONDS = 900;
const DEFAULT_MAX_PRESIGN_TTL_SECONDS = 86400;

const ACCESS_KEY_FORMAT_REGEX = /^[A-Za-z0-9_.\-!#^&*@$%~+=]{8,128}$/;

const PRESIGN_SIGV4_QUERY_KEYS = new Set([
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-expires",
    "x-amz-signedheaders",
    "x-amz-signature",
    "x-amz-security-token",
]);

const CLOAKED_HEADER_PREFIXES = [
    "x-amz-",
    "x-scw-",
    "x-ovh-",
    "x-rgw-",
    "x-oss-",
    "x-cos-",
    "x-b2-",
    "x-guploader-",
];

const CLOAKED_EXACT_HEADERS = new Set([
    "server",
    "x-powered-by",
    "via",
]);

function setBoundedMap(map, maxEntries, key, value) {
    if (map.has(key)) {
        map.delete(key);
    } else if (map.size >= maxEntries) {
        const oldestKey = map.keys().next().value;
        if (oldestKey !== undefined) map.delete(oldestKey);
    }
    map.set(key, value);
}

function getLicensesKv(env) {
    return env?.LICENSES_KV || env?.LICENSES || null;
}

function getR2Gateway(env) {
    return env?.R2_GATEWAY || env?.S3GW_R2 || null;
}

async function getCachedKV(env, key, customNegativeTtlMs = NEGATIVE_CACHE_TTL_MS) {
    const now = Date.now();
    if (kvCache.has(key)) {
        const cached = kvCache.get(key);
        const ttl = cached.ttl ?? (cached.data === null ? customNegativeTtlMs : CACHE_TTL_MS);
        if (now - cached.timestamp < ttl) {
            kvCache.delete(key);
            kvCache.set(key, cached);
            return cached.data;
        }
        kvCache.delete(key);
    }
    const kv = getLicensesKv(env);
    if (!kv) return null;
    const data = await kv.get(key, { type: "json" });
    const ttl = data === null ? customNegativeTtlMs : CACHE_TTL_MS;
    setBoundedMap(kvCache, MAX_KV_CACHE_ENTRIES, key, { data, timestamp: now, ttl });
    return data;
}

function setQuarantineCacheImmediate(licenseKey, quarantineObj, durationSeconds) {
    const ttl = Math.min(CACHE_TTL_MS, Math.max(1000, durationSeconds * 1000));
    setBoundedMap(kvCache, MAX_KV_CACHE_ENTRIES, `quarantine:${licenseKey}`, {
        data: quarantineObj,
        timestamp: Date.now(),
        ttl
    });
}

function fullyDecodeURIComponent(str, maxPasses = 5) {
    let current = String(str ?? "");
    for (let i = 0; i < maxPasses; i++) {
        try {
            const decoded = decodeURIComponent(current);
            if (decoded === current) break;
            current = decoded;
        } catch (e) {
            const partial = current.replace(/%[0-9a-fA-F]{2}/g, (m) => {
                try { return decodeURIComponent(m); } catch (_) { return m; }
            });
            if (partial === current) break;
            current = partial;
        }
    }
    return current;
}

function normalizeAndInspectPath(rawPath) {
    const rawStr = String(rawPath || "/");
    const rawSegments = rawStr.split("/");
    const decodedSegments = [];
    let hasTraversal = false;

    for (const seg of rawSegments) {
        if (!seg) continue;
        const dec = fullyDecodeURIComponent(seg).replace(/\\/g, "/");
        const subParts = dec.split("/");
        for (const sub of subParts) {
            if (!sub) continue;
            if (sub === "." || sub === "..") {
                hasTraversal = true;
            }
            decodedSegments.push(sub);
        }
    }

    const normalizedPath = "/" + decodedSegments.join("/") + (rawStr.endsWith("/") && decodedSegments.length > 0 ? "/" : "");
    return {
        normalizedPath,
        segments: decodedSegments,
        hasTraversal
    };
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const configuredGatewayHost = (env.GATEWAY_HOST || "gateway.s3gw.com").toLowerCase();
        const corsAllowedOrigins = parseAllowedOrigins(env.CORS_ALLOWED_ORIGINS);

        if (request.method === "OPTIONS") {
            return handleOptionsPreflight(request, corsAllowedOrigins);
        }

        const startMs = Date.now();
        const authHeader = request.headers.get("Authorization") || "";
        const sourceIP = (request.headers.get("CF-Connecting-IP") || "").trim();
        const method = request.method;
        const queryString = url.search;
        const contentLength = parseInt(request.headers.get("Content-Length") || "0", 10);
        const userAgent = request.headers.get("User-Agent") || "";
        const country = request.cf?.country || "Unknown";
        const city = request.cf?.city || "Unknown";
        const asn = request.cf?.asn || "N/A";
        const asOrganization = request.cf?.asOrganization || "Unknown ISP";

        let rawTargetPath = url.pathname;
        const hostName = url.hostname.toLowerCase();
        if (hostName !== configuredGatewayHost && hostName.endsWith("." + configuredGatewayHost)) {
            const vhBucket = hostName.slice(0, -(configuredGatewayHost.length + 1));
            rawTargetPath = `/${vhBucket}${rawTargetPath === "/" ? "" : rawTargetPath}`;
        }

        if (rawTargetPath === "/_s3gw/presign") {
            return handlePresignMintRequest({
                request, env, ctx, url, startMs, configuredGatewayHost, corsAllowedOrigins,
                authHeader, sourceIP, method, contentLength, userAgent, country, city, asn, asOrganization
            });
        }

        if (rawTargetPath.startsWith("/dl/") || rawTargetPath.startsWith("/s/")) {
            return handleCloakedTokenRequest({
                request, env, ctx, url, rawTargetPath, startMs, configuredGatewayHost, corsAllowedOrigins,
                sourceIP, method, contentLength, userAgent, country, city, asn, asOrganization
            });
        }

        let { normalizedPath, segments: pathParts, hasTraversal } = normalizeAndInspectPath(rawTargetPath);
        let requestedBucket = pathParts.length > 0 ? pathParts[0] : "";
        let s3Operation = resolveS3Operation(method, normalizedPath, queryString, request.headers);

        const logAndReject = (logLicenseKey, gwKeyUsed, bucketForLog, status, code, message, blockReason, riskLevel = "high", policyCorsOrigins = corsAllowedOrigins, authMeta = undefined) => {
            const durationMs = Date.now() - startMs;
            const logEntry = buildLogEntry({
                licenseKey: logLicenseKey,
                gwHost: configuredGatewayHost,
                sourceIP,
                country,
                city,
                asn,
                asOrganization,
                userAgent,
                gwAccessKey: gwKeyUsed,
                method,
                s3Operation,
                path: normalizedPath,
                bucket: bucketForLog || requestedBucket || "unknown",
                contentLength,
                status,
                durationMs,
                authMeta,
                securityDecision: {
                    allowed: false,
                    status,
                    code,
                    message,
                    blockReason,
                    riskLevel
                }
            });
            if (env.R2_GATEWAY && ctx?.waitUntil) {
                ctx.waitUntil(writeLog(env, logLicenseKey, logEntry));
            }
            return errorResponse(status, code, message, configuredGatewayHost, request, policyCorsOrigins);
        };

        const isHeaderSigV4 = authHeader.startsWith("AWS4-HMAC-SHA256");
        const isQuerySigV4 = !isHeaderSigV4 && (url.searchParams.get("X-Amz-Algorithm") === "AWS4-HMAC-SHA256");
        const authMeta = { mode: isQuerySigV4 ? "sigv4_presigned_query" : "sigv4_header" };

        if (!isHeaderSigV4 && !isQuerySigV4) {
            return logAndReject(
                "_unauthenticated",
                "NONE",
                requestedBucket,
                403,
                "AccessDenied",
                "AWS Signature V4 ou lien pré-signé requis.",
                "MISSING_AWS_SIGV4_AUTH",
                "medium",
                corsAllowedOrigins,
                authMeta
            );
        }

        const gwAccessKeyReceived = isQuerySigV4
            ? extractAccessKeyFromQuery(url.searchParams)
            : extractAccessKeyFromAuth(authHeader);

        if (!gwAccessKeyReceived || gwAccessKeyReceived === "-" || !ACCESS_KEY_FORMAT_REGEX.test(gwAccessKeyReceived)) {
            return logAndReject(
                "_unauthenticated",
                gwAccessKeyReceived || "INVALID",
                requestedBucket,
                403,
                "InvalidAccessKeyId",
                "Access key invalide.",
                "MALFORMED_ACCESS_KEY_ID",
                "high",
                corsAllowedOrigins,
                authMeta
            );
        }

        const licenseKey = gwAccessKeyReceived;

        const [license, keyQuarantine, ipQuarantine] = await Promise.all([
            getCachedKV(env, licenseKey),
            getCachedKV(env, `quarantine:${licenseKey}`),
            sourceIP ? getCachedKV(env, `quarantine:${licenseKey}:${sourceIP}`) : Promise.resolve(null)
        ]);
        const quarantine = keyQuarantine || ipQuarantine;

        if (!license) {
            return logAndReject(
                "_unauthenticated",
                gwAccessKeyReceived,
                requestedBucket,
                403,
                "InvalidAccessKeyId",
                "Clé de licence inconnue.",
                "UNKNOWN_LICENSE_KEY",
                "high",
                corsAllowedOrigins,
                authMeta
            );
        }

        const licenseCorsOrigins = parseAllowedOrigins(
            license.security_policy?.allowed_origins ||
            license.securityPolicy?.allowedOrigins ||
            license.cors_allowed_origins ||
            env.CORS_ALLOWED_ORIGINS
        );

        if (!license.activated) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                403,
                "AccessDenied",
                "Licence désactivée.",
                "LICENSE_DEACTIVATED",
                "medium",
                licenseCorsOrigins,
                authMeta
            );
        }

        if (new Date(license.expires_at) < new Date()) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                403,
                "AccessDenied",
                "Licence expirée.",
                "LICENSE_EXPIRED",
                "medium",
                licenseCorsOrigins,
                authMeta
            );
        }

        if (!license.gateway?.enabled) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                403,
                "AccessDenied",
                "Gateway non activée pour cette licence.",
                "GATEWAY_DISABLED",
                "medium",
                licenseCorsOrigins,
                authMeta
            );
        }

        const licenseGatewayAccessKey = license.gateway.access_key || license.gateway.accessKey;
        if (licenseGatewayAccessKey !== gwAccessKeyReceived) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                403,
                "InvalidAccessKeyId",
                "Access key ne correspond pas à cette licence.",
                "ACCESS_KEY_MISMATCH",
                "high",
                licenseCorsOrigins,
                authMeta
            );
        }

        const presignedCfg = resolvePresignedConfig(license);
        const licenseGatewaySecretKey = license.gateway.secret_key || license.gateway.secretKey;

        if (isQuerySigV4) {
            if (!presignedCfg.enabled || !presignedCfg.allowSigv4Query) {
                return logAndReject(
                    licenseKey,
                    gwAccessKeyReceived,
                    license.bucket,
                    403,
                    "AccessDenied",
                    "Presigned URLs are disabled for this gateway license.",
                    "PRESIGNED_URLS_DISABLED",
                    "high",
                    licenseCorsOrigins,
                    authMeta
                );
            }
            if (!presignedCfg.allowedMethods.includes(method)) {
                return logAndReject(
                    licenseKey,
                    gwAccessKeyReceived,
                    license.bucket,
                    403,
                    "AccessDenied",
                    `HTTP method '${method}' is not allowed for presigned URLs.`,
                    "PRESIGNED_METHOD_NOT_ALLOWED",
                    "high",
                    licenseCorsOrigins,
                    authMeta
                );
            }
        }

        const sigResult = isQuerySigV4
            ? await verifyAwsSigV4PresignedQuery(request, licenseGatewaySecretKey, url, presignedCfg.maxTtlSeconds)
            : await verifyAwsSigV4(request, licenseGatewaySecretKey, url);

        if (!sigResult.valid) {
            const isExpired = sigResult.reason === "RequestExpired";
            const isSkew = sigResult.reason === "RequestTimeTooSkewed" || isExpired;
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                403,
                isExpired ? "AccessDenied" : (isSkew ? "RequestTimeTooSkewed" : "SignatureDoesNotMatch"),
                isExpired ? "Request has expired." : (isSkew ? "L'horodatage de la requête dépasse la fenêtre autorisée." : "Signature AWS invalide."),
                isExpired ? "PRESIGNED_URL_EXPIRED" : (isSkew ? "SIGV4_REPLAY_OR_CLOCK_SKEW" : "INVALID_AWS_SIGNATURE"),
                isExpired ? "medium" : "high",
                licenseCorsOrigins,
                authMeta
            );
        }

        if (hasTraversal) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                400,
                "InvalidURI",
                "Path traversal sequences are not allowed.",
                "PATH_TRAVERSAL_DETECTED",
                "critical",
                licenseCorsOrigins,
                authMeta
            );
        }

        if (requestedBucket === "_" && license.bucket) {
            const restSegments = pathParts.slice(1);
            rawTargetPath = `/${license.bucket}/${restSegments.join("/")}${rawTargetPath.endsWith("/") && restSegments.length > 0 ? "/" : ""}`;
            normalizedPath = `/${license.bucket}${restSegments.length > 0 ? "/" + restSegments.join("/") : ""}${normalizedPath.endsWith("/") && restSegments.length > 0 ? "/" : ""}`;
            pathParts = [license.bucket, ...restSegments];
            requestedBucket = license.bucket;
            s3Operation = resolveS3Operation(method, normalizedPath, isQuerySigV4 ? stripSigV4QueryParams(url.searchParams) : queryString, request.headers);
        } else if (isQuerySigV4) {
            s3Operation = resolveS3Operation(method, normalizedPath, stripSigV4QueryParams(url.searchParams), request.headers);
        }

        if (requestedBucket && requestedBucket !== license.bucket) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                requestedBucket,
                403,
                "AccessDenied",
                "Access to this bucket is not allowed by your license.",
                "UNAUTHORIZED_BUCKET_ACCESS",
                "high",
                licenseCorsOrigins,
                authMeta
            );
        }

        const rawCopySource = request.headers.get("x-amz-copy-source");
        if (rawCopySource !== null) {
            const copyCheck = validateCopySourceHeader(rawCopySource, license.bucket);
            if (!copyCheck.valid) {
                return logAndReject(
                    licenseKey,
                    gwAccessKeyReceived,
                    copyCheck.sourceBucket || license.bucket,
                    403,
                    "AccessDenied",
                    copyCheck.message,
                    copyCheck.blockReason,
                    "critical",
                    licenseCorsOrigins,
                    authMeta
                );
            }
        }

        if (quarantine) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                429,
                "SlowDown",
                `S3GW Exfiltration Guard: Access key is quarantined (${quarantine.reason || "Quota exceeded"}). Try again later.`,
                "QUARANTINED_BY_QUOTA",
                "high",
                licenseCorsOrigins,
                authMeta
            );
        }

        const secDecision = checkSecurityPolicy(env, request, url, normalizedPath, license, s3Operation, sourceIP, country, asn, userAgent);
        if (!secDecision.allowed) {
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                secDecision.status || 403,
                secDecision.code || "AccessDenied",
                secDecision.message,
                secDecision.blockReason || "SECURITY_POLICY_VIOLATION",
                secDecision.riskLevel || "high",
                licenseCorsOrigins,
                authMeta
            );
        }

        if (!requestedBucket && license.bucket) {
            if (method === "GET" && !isQuerySigV4) {
                const synthResp = buildSyntheticListBucketsResponse(license, request, licenseCorsOrigins);
                const durationMs = Date.now() - startMs;
                const logEntry = buildLogEntry({
                    licenseKey,
                    gwHost: configuredGatewayHost,
                    sourceIP,
                    country,
                    city,
                    asn,
                    asOrganization,
                    userAgent,
                    gwAccessKey: gwAccessKeyReceived,
                    method,
                    s3Operation: "listBuckets",
                    path: "/",
                    bucket: license.bucket,
                    contentLength: 0,
                    status: 200,
                    durationMs,
                    authMeta,
                    securityDecision: undefined
                });
                if (env.R2_GATEWAY && ctx?.waitUntil) {
                    ctx.waitUntil(writeLog(env, licenseKey, logEntry));
                }
                return synthResp;
            }
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                403,
                "AccessDenied",
                "Listing or mutating root without bucket is not allowed. Please specify your bucket.",
                "ROOT_OPERATION_NOT_ALLOWED",
                "medium",
                licenseCorsOrigins,
                authMeta
            );
        }

        const disableDlpKv = isDlpKvWritesDisabled(env, license);

        let deleteObjectsCount = 1;
        let preReadBodyBuffer = null;
        if (s3Operation === "deleteObjects" && request.body && contentLength <= 2 * 1024 * 1024) {
            try {
                preReadBodyBuffer = await request.arrayBuffer();
                const xmlText = new TextDecoder().decode(preReadBodyBuffer);
                deleteObjectsCount = countDeleteObjectsInXml(xmlText);
            } catch (e) {
                deleteObjectsCount = 1;
            }

            const quotas = (license.security_policy || license.securityPolicy || {}).dlp_quotas || (license.security_policy || license.securityPolicy || {}).dlpQuotas;
            if (!disableDlpKv && quotas?.max_delete_requests_per_minute && deleteObjectsCount > quotas.max_delete_requests_per_minute) {
                ctx.waitUntil(trackDlpQuotasAndQuarantine(env, licenseKey, sourceIP, license, method, s3Operation, 0, deleteObjectsCount));
                return logAndReject(
                    licenseKey,
                    gwAccessKeyReceived,
                    license.bucket,
                    429,
                    "SlowDown",
                    `S3GW Exfiltration Guard: Batch delete of ${deleteObjectsCount} objects exceeds per-minute delete quota (${quotas.max_delete_requests_per_minute}). Access key is now quarantined.`,
                    "QUOTA_DELETE_REQUESTS_PER_MINUTE_EXCEEDED",
                    "critical",
                    licenseCorsOrigins,
                    authMeta
                );
            }
        }

        const shouldLog = decideShouldLog(method, s3Operation, contentLength);

        const backendResp = await forwardToBackend(request, url, rawTargetPath, license, env, preReadBodyBuffer, {
            stripSigV4Query: isQuerySigV4
        });
        const durationMs = Date.now() - startMs;

        const respBytes = parseInt(backendResp.headers.get("Content-Length") || "0", 10);
        const actualBytes = (method === "GET" || s3Operation === "getObject") ? respBytes : contentLength;

        if (!disableDlpKv && (backendResp.ok || backendResp.status === 304)) {
            ctx.waitUntil(trackDlpQuotasAndQuarantine(env, licenseKey, sourceIP, license, method, s3Operation, actualBytes, deleteObjectsCount));
        }

        if (shouldLog) {
            const logEntry = buildLogEntry({
                licenseKey,
                gwHost: configuredGatewayHost,
                sourceIP,
                country,
                city,
                asn,
                asOrganization,
                userAgent,
                gwAccessKey: gwAccessKeyReceived,
                method,
                s3Operation,
                path: normalizedPath,
                bucket: license.bucket,
                contentLength: actualBytes,
                status: backendResp.status,
                durationMs,
                authMeta,
                securityDecision: undefined
            });

            ctx.waitUntil(writeLog(env, licenseKey, logEntry));
        }

        const respHeaders = sanitizeBackendResponseHeaders(backendResp.headers, license, {
            fullCloak: isQuerySigV4
        });
        applyCorsHeaders(respHeaders, request, licenseCorsOrigins);
        if (!backendResp.ok) {
            respHeaders.set("Cache-Control", "no-transform");
        }

        return new Response(backendResp.body, {
            status: backendResp.status,
            statusText: backendResp.statusText,
            headers: respHeaders,
        });
    },
};

function resolvePresignedConfig(license) {
    const gw = license?.gateway || {};
    const cfg = gw.presigned_urls || gw.presignedUrls || license?.presigned_urls || license?.presignedUrls || {};
    const enabled = cfg.enabled !== false;
    const allowEncryptedTokens = cfg.allow_encrypted_tokens !== false && cfg.allowEncryptedTokens !== false;
    const allowHmacTokens = cfg.allow_hmac_tokens !== false && cfg.allowHmacTokens !== false;
    const allowSigv4Query = cfg.allow_sigv4_query !== false && cfg.allowSigv4Query !== false;
    const allowBearerMinting = cfg.allow_bearer_minting !== false && cfg.allowBearerMinting !== false;
    const enforceSingleUse = cfg.enforce_single_use === true || cfg.enforceSingleUse === true;
    const defaultTtlSeconds = Math.max(1, parseInt(cfg.default_ttl_seconds ?? cfg.defaultTtlSeconds ?? DEFAULT_PRESIGN_TTL_SECONDS, 10) || DEFAULT_PRESIGN_TTL_SECONDS);
    const maxTtlSeconds = Math.max(defaultTtlSeconds, parseInt(cfg.max_ttl_seconds ?? cfg.maxTtlSeconds ?? DEFAULT_MAX_PRESIGN_TTL_SECONDS, 10) || DEFAULT_MAX_PRESIGN_TTL_SECONDS);
    const rawMethods = cfg.allowed_methods || cfg.allowedMethods || ["GET", "HEAD"];
    const allowedMethods = Array.isArray(rawMethods) && rawMethods.length > 0
        ? rawMethods.map(m => String(m).trim().toUpperCase())
        : ["GET", "HEAD"];
    if (allowedMethods.includes("GET") && !allowedMethods.includes("HEAD")) {
        allowedMethods.push("HEAD");
    }
    return {
        enabled,
        allowEncryptedTokens,
        allowHmacTokens,
        allowSigv4Query,
        allowBearerMinting,
        enforceSingleUse,
        defaultTtlSeconds,
        maxTtlSeconds,
        allowedMethods
    };
}

function base64UrlEncodeBytes(bytes) {
    let bin = "";
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < u8.length; i++) {
        bin += String.fromCharCode(u8[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecodeToBytes(str) {
    try {
        if (!str || typeof str !== "string" || !/^[A-Za-z0-9_-]+$/.test(str)) return null;
        let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4 !== 0) b64 += "=";
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            out[i] = bin.charCodeAt(i);
        }
        return out;
    } catch (_) {
        return null;
    }
}

async function getCachedTokenCryptoKeys(secret) {
    const cacheKey = `tok:${secret}`;
    const now = Date.now();
    if (tokenCryptoKeyCache.has(cacheKey)) {
        const entry = tokenCryptoKeyCache.get(cacheKey);
        if (now - entry.timestamp < SIGNING_KEY_TTL_MS) {
            tokenCryptoKeyCache.delete(cacheKey);
            tokenCryptoKeyCache.set(cacheKey, entry);
            return entry;
        }
        tokenCryptoKeyCache.delete(cacheKey);
    }
    const [aesRaw, hmacKeyBytes] = await Promise.all([
        hmacRaw(enc("S3GW_CLOAK_AES_V1"), secret),
        hmacRaw(enc("S3GW_CLOAK_HMAC_V1"), secret)
    ]);
    const [aesKey, hmacKey] = await Promise.all([
        crypto.subtle.importKey("raw", aesRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]),
        crypto.subtle.importKey("raw", hmacKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
    ]);
    const entry = { aesKey, hmacKey, timestamp: now };
    setBoundedMap(tokenCryptoKeyCache, MAX_TOKEN_KEY_CACHE_ENTRIES, cacheKey, entry);
    return entry;
}

async function mintCloakedToken(accessKey, secretKey, payloadObj, mode = "encrypted") {
    const akB64 = base64UrlEncodeBytes(enc(accessKey));
    const jsonBytes = enc(JSON.stringify(payloadObj));
    const { aesKey, hmacKey } = await getCachedTokenCryptoKeys(secretKey);

    if (mode === "hmac") {
        const payloadB64 = base64UrlEncodeBytes(jsonBytes);
        const signingInput = `v1.${akB64}.${payloadB64}`;
        const sigBytes = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, enc(signingInput)));
        return `${signingInput}.${base64UrlEncodeBytes(sigBytes)}`;
    }

    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const cipherBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: enc(accessKey) },
        aesKey,
        jsonBytes
    );
    const cipherBytes = new Uint8Array(cipherBuf);
    const combined = new Uint8Array(iv.length + cipherBytes.length);
    combined.set(iv, 0);
    combined.set(cipherBytes, iv.length);
    return `v1e.${akB64}.${base64UrlEncodeBytes(combined)}`;
}

function extractAccessKeyFromCloakedToken(rawToken) {
    if (!rawToken || typeof rawToken !== "string") return null;
    const parts = rawToken.split(".");
    if (parts.length < 3) return null;
    const version = parts[0];
    if (version !== "v1e" && version !== "v1") return null;
    const akBytes = base64UrlDecodeToBytes(parts[1]);
    if (!akBytes) return null;
    try {
        const ak = new TextDecoder().decode(akBytes);
        return ACCESS_KEY_FORMAT_REGEX.test(ak) ? { version, accessKey: ak, parts } : null;
    } catch (_) {
        return null;
    }
}

async function verifyAndDecodeCloakedToken(parsedToken, secretKey, presignedCfg) {
    try {
        const { version, accessKey, parts } = parsedToken;
        const { aesKey, hmacKey } = await getCachedTokenCryptoKeys(secretKey);

        let payloadBytes = null;
        if (version === "v1e") {
            if (!presignedCfg.allowEncryptedTokens) return { valid: false, reason: "EncryptedTokensDisabled" };
            if (parts.length !== 3) return { valid: false, reason: "MalformedToken" };
            const combined = base64UrlDecodeToBytes(parts[2]);
            if (!combined || combined.byteLength < 29) return { valid: false, reason: "MalformedCiphertext" };
            const iv = combined.subarray(0, 12);
            const ciphertext = combined.subarray(12);
            const decryptedBuf = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv, additionalData: enc(accessKey) },
                aesKey,
                ciphertext
            );
            payloadBytes = new Uint8Array(decryptedBuf);
        } else if (version === "v1") {
            if (!presignedCfg.allowHmacTokens) return { valid: false, reason: "HmacTokensDisabled" };
            if (parts.length !== 4) return { valid: false, reason: "MalformedToken" };
            const signingInput = `v1.${parts[1]}.${parts[2]}`;
            const receivedSig = base64UrlDecodeToBytes(parts[3]);
            if (!receivedSig || receivedSig.byteLength !== 32) return { valid: false, reason: "MalformedSignature" };
            const computedSig = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, enc(signingInput)));
            if (!timingSafeEqualBytes(computedSig, receivedSig)) {
                return { valid: false, reason: "SignatureDoesNotMatch" };
            }
            payloadBytes = base64UrlDecodeToBytes(parts[2]);
            if (!payloadBytes) return { valid: false, reason: "MalformedPayload" };
        } else {
            return { valid: false, reason: "UnsupportedVersion" };
        }

        const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
        if (!payload || typeof payload !== "object" || typeof payload.k !== "string" || !payload.k) {
            return { valid: false, reason: "InvalidPayloadClaims" };
        }

        const nowSec = Math.floor(Date.now() / 1000);
        const expSec = Number(payload.exp);
        if (!Number.isFinite(expSec) || nowSec > expSec) {
            return { valid: false, reason: "TokenExpired", payload };
        }

        const iatSec = Number(payload.iat || nowSec);
        if (expSec - iatSec > presignedCfg.maxTtlSeconds + 60) {
            return { valid: false, reason: "TtlExceedsPolicyMax", payload };
        }

        return {
            valid: true,
            mode: version === "v1e" ? "cloaked_token_encrypted" : "cloaked_token_hmac",
            payload
        };
    } catch (_) {
        return { valid: false, reason: "InvalidOrTamperedToken" };
    }
}

async function verifyConstantTimeSecret(expectedSecret, providedSecret) {
    if (!expectedSecret || !providedSecret) return false;
    const [h1, h2] = await Promise.all([
        crypto.subtle.digest("SHA-256", enc(String(expectedSecret))),
        crypto.subtle.digest("SHA-256", enc(String(providedSecret)))
    ]);
    return timingSafeEqualBytes(new Uint8Array(h1), new Uint8Array(h2));
}

function isDlpKvWritesDisabled(env, license) {
    const envDisableStr = String(env?.DISABLE_DLP_KV_WRITES || "").trim().toLowerCase();
    if (envDisableStr === "true" || envDisableStr === "1" || env?.DISABLE_DLP_KV_WRITES === true) return true;
    if (license?.disable_dlp_kv_writes === true || String(license?.disable_dlp_kv_writes || "").trim().toLowerCase() === "true") return true;
    const sec = license?.security_policy || license?.securityPolicy || {};
    const quotas = sec.dlp_quotas ?? sec.dlpQuotas;
    if (quotas === false || quotas?.enabled === false) return true;
    return false;
}

async function checkSingleUseTokenConsumed(env, licenseKey, jti, disableKv = false) {
    if (!jti) return true;
    const cacheKey = `${licenseKey}:${jti}`;
    const now = Date.now();
    if (consumedTokenCache.has(cacheKey)) {
        const exp = consumedTokenCache.get(cacheKey);
        if (now < exp) return true;
        consumedTokenCache.delete(cacheKey);
    }
    if (disableKv) return false;
    const kv = getLicensesKv(env);
    if (!kv) return false;
    const kvVal = await kv.get(`used_token:${cacheKey}`);
    return kvVal !== null;
}

async function markSingleUseTokenConsumed(env, licenseKey, jti, remainingTtlSeconds, disableKv = false) {
    if (!jti) return;
    const cacheKey = `${licenseKey}:${jti}`;
    const ttlSec = Math.max(60, Math.min(86400, (Number(remainingTtlSeconds) || 900) + 60));
    setBoundedMap(consumedTokenCache, MAX_CONSUMED_TOKEN_CACHE_ENTRIES, cacheKey, Date.now() + ttlSec * 1000);
    if (disableKv) return;
    try {
        const kv = getLicensesKv(env);
        if (kv) {
            await kv.put(`used_token:${cacheKey}`, "1", { expirationTtl: ttlSec });
        }
    } catch (_) {
    }
}

async function handlePresignMintRequest({
    request, env, ctx, url, startMs, configuredGatewayHost, corsAllowedOrigins,
    authHeader, sourceIP, method, contentLength, userAgent, country, city, asn, asOrganization
}) {
    const s3Operation = "createPresignedUrl";
    const jsonReject = (logLicenseKey, gwKeyUsed, bucketForLog, status, code, message, blockReason, riskLevel = "high", policyCorsOrigins = corsAllowedOrigins, authMeta = { mode: "presign_mint" }) => {
        const durationMs = Date.now() - startMs;
        const logEntry = buildLogEntry({
            licenseKey: logLicenseKey,
            gwHost: configuredGatewayHost,
            sourceIP,
            country,
            city,
            asn,
            asOrganization,
            userAgent,
            gwAccessKey: gwKeyUsed,
            method,
            s3Operation,
            path: "/_s3gw/presign",
            bucket: bucketForLog || "unknown",
            contentLength,
            status,
            durationMs,
            authMeta,
            securityDecision: { allowed: false, status, code, message, blockReason, riskLevel }
        });
        if (env.R2_GATEWAY && ctx?.waitUntil) {
            ctx.waitUntil(writeLog(env, logLicenseKey, logEntry));
        }
        const headers = new Headers({
            "Content-Type": "application/json; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Server": "s3gw"
        });
        applyCorsHeaders(headers, request, policyCorsOrigins);
        return new Response(JSON.stringify({ error: code, message }), { status, headers });
    };

    if (method !== "POST") {
        return jsonReject("_unauthenticated", "NONE", "unknown", 405, "MethodNotAllowed", "Only POST is allowed on /_s3gw/presign.", "INVALID_MINT_METHOD", "low");
    }

    let gwAccessKeyReceived = "";
    let bearerSecretProvided = null;
    const isSigV4 = authHeader.startsWith("AWS4-HMAC-SHA256");
    const isBearer = authHeader.startsWith("Bearer ");

    if (isSigV4) {
        gwAccessKeyReceived = extractAccessKeyFromAuth(authHeader);
    } else if (isBearer) {
        const rawCreds = authHeader.slice(7).trim();
        const sepIdx = rawCreds.indexOf(":");
        if (sepIdx > 0) {
            gwAccessKeyReceived = rawCreds.slice(0, sepIdx).trim();
            bearerSecretProvided = rawCreds.slice(sepIdx + 1).trim();
        }
    } else {
        return jsonReject("_unauthenticated", "NONE", "unknown", 403, "AccessDenied", "Authentication required (AWS4-HMAC-SHA256 or Bearer <access_key>:<secret_key>).", "MISSING_MINT_AUTH", "medium");
    }

    if (!gwAccessKeyReceived || !ACCESS_KEY_FORMAT_REGEX.test(gwAccessKeyReceived)) {
        return jsonReject("_unauthenticated", gwAccessKeyReceived || "INVALID", "unknown", 403, "InvalidAccessKeyId", "Invalid gateway access key.", "MALFORMED_ACCESS_KEY_ID", "high");
    }

    const licenseKey = gwAccessKeyReceived;
    const [license, keyQuarantine, ipQuarantine] = await Promise.all([
        getCachedKV(env, licenseKey),
        getCachedKV(env, `quarantine:${licenseKey}`),
        sourceIP ? getCachedKV(env, `quarantine:${licenseKey}:${sourceIP}`) : Promise.resolve(null)
    ]);
    const quarantine = keyQuarantine || ipQuarantine;

    if (!license) {
        return jsonReject("_unauthenticated", gwAccessKeyReceived, "unknown", 403, "InvalidAccessKeyId", "Unknown license key.", "UNKNOWN_LICENSE_KEY", "high");
    }

    const licenseCorsOrigins = parseAllowedOrigins(
        license.security_policy?.allowed_origins ||
        license.securityPolicy?.allowedOrigins ||
        license.cors_allowed_origins ||
        env.CORS_ALLOWED_ORIGINS
    );

    if (!license.activated || new Date(license.expires_at) < new Date() || !license.gateway?.enabled) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "AccessDenied", "License or gateway is inactive or expired.", "LICENSE_INACTIVE_OR_EXPIRED", "medium", licenseCorsOrigins);
    }

    const presignedCfg = resolvePresignedConfig(license);
    if (!presignedCfg.enabled) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "AccessDenied", "Presigned URLs are disabled for this license.", "PRESIGNED_URLS_DISABLED", "high", licenseCorsOrigins);
    }

    const licenseGatewayAccessKey = license.gateway.access_key || license.gateway.accessKey;
    const licenseGatewaySecretKey = license.gateway.secret_key || license.gateway.secretKey;
    if (licenseGatewayAccessKey !== gwAccessKeyReceived) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "InvalidAccessKeyId", "Access key mismatch.", "ACCESS_KEY_MISMATCH", "high", licenseCorsOrigins);
    }

    if (isBearer) {
        if (!presignedCfg.allowBearerMinting) {
            return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "AccessDenied", "Bearer token minting is disabled; use AWS SigV4.", "BEARER_MINTING_DISABLED", "high", licenseCorsOrigins);
        }
        const secretValid = await verifyConstantTimeSecret(licenseGatewaySecretKey, bearerSecretProvided);
        if (!secretValid) {
            return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "SignatureDoesNotMatch", "Invalid gateway secret key.", "INVALID_BEARER_SECRET", "high", licenseCorsOrigins);
        }
    } else {
        const sigResult = await verifyAwsSigV4(request, licenseGatewaySecretKey, url);
        if (!sigResult.valid) {
            return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "SignatureDoesNotMatch", "Invalid AWS SigV4 signature.", "INVALID_AWS_SIGNATURE", "high", licenseCorsOrigins);
        }
    }

    if (quarantine) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 429, "SlowDown", `Access key is quarantined (${quarantine.reason || "Quota exceeded"}).`, "QUARANTINED_BY_QUOTA", "high", licenseCorsOrigins);
    }

    let bodyObj = null;
    try {
        bodyObj = await request.json();
    } catch (_) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 400, "MalformedJSON", "Request body must be valid JSON.", "MALFORMED_MINT_JSON", "low", licenseCorsOrigins);
    }

    const rawKey = String(bodyObj?.key || bodyObj?.object_key || bodyObj?.path || "").trim();
    if (!rawKey) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 400, "InvalidArgument", "Missing required 'key' field.", "MISSING_OBJECT_KEY", "low", licenseCorsOrigins);
    }

    const { segments: keySegments, hasTraversal } = normalizeAndInspectPath(rawKey);
    if (hasTraversal || keySegments.length === 0) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 400, "InvalidURI", "Invalid or traversal object key.", "PATH_TRAVERSAL_DETECTED", "critical", licenseCorsOrigins);
    }

    const cleanSegments = (keySegments[0] === license.bucket && keySegments.length > 1)
        ? keySegments.slice(1)
        : keySegments;
    const cleanObjectKey = cleanSegments.join("/");
    const simulatedTargetPath = `/${license.bucket}/${cleanObjectKey}`;

    const requestedMethod = String(bodyObj?.method || "GET").trim().toUpperCase();
    if (!presignedCfg.allowedMethods.includes(requestedMethod)) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "AccessDenied", `Method '${requestedMethod}' is not allowed for presigned URLs on this bucket.`, "PRESIGNED_METHOD_NOT_ALLOWED", "high", licenseCorsOrigins);
    }

    const simulatedOp = requestedMethod === "PUT" ? "putObject" : (requestedMethod === "HEAD" ? "headObject" : "getObject");
    const secDecision = checkSecurityPolicy(env, request, url, simulatedTargetPath, license, simulatedOp, sourceIP, country, asn, userAgent);
    if (!secDecision.allowed) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, secDecision.status || 403, secDecision.code || "AccessDenied", secDecision.message, secDecision.blockReason, secDecision.riskLevel || "high", licenseCorsOrigins);
    }

    const reqTtl = parseInt(bodyObj?.expires_in ?? bodyObj?.ttl ?? presignedCfg.defaultTtlSeconds, 10);
    const effectiveTtl = Math.min(presignedCfg.maxTtlSeconds, Math.max(1, isNaN(reqTtl) ? presignedCfg.defaultTtlSeconds : reqTtl));
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = nowSec + effectiveTtl;
    const singleUse = Boolean(bodyObj?.single_use || bodyObj?.singleUse || presignedCfg.enforceSingleUse);
    const jti = generateRandomHex(8);
    const correlationId = bodyObj?.correlation_id || bodyObj?.correlationId ? String(bodyObj.correlation_id || bodyObj.correlationId).slice(0, 128) : undefined;
    const ipBind = bodyObj?.ip_bind || bodyObj?.ipBind ? String(bodyObj.ip_bind || bodyObj.ipBind).trim() : undefined;

    if (ipBind && !parseIpAddress(ipBind.split("/")[0])) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 400, "InvalidArgument", "Invalid ip_bind IP/CIDR format.", "INVALID_IP_BIND", "low", licenseCorsOrigins);
    }

    let disposition = bodyObj?.disposition || bodyObj?.content_disposition ? String(bodyObj.disposition || bodyObj.content_disposition).trim() : undefined;
    if (!disposition && bodyObj?.filename) {
        const safeFn = String(bodyObj.filename).replace(/["\r\n\\]/g, "_");
        disposition = `attachment; filename="${safeFn}"`;
    }
    const contentTypeOverride = bodyObj?.content_type || bodyObj?.contentType ? String(bodyObj.content_type || bodyObj.contentType).trim() : undefined;

    const requestedMode = String(bodyObj?.mode || "encrypted").trim().toLowerCase() === "hmac" ? "hmac" : "encrypted";
    if (requestedMode === "encrypted" && !presignedCfg.allowEncryptedTokens) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "AccessDenied", "Encrypted tokens are disabled.", "ENCRYPTED_TOKENS_DISABLED", "medium", licenseCorsOrigins);
    }
    if (requestedMode === "hmac" && !presignedCfg.allowHmacTokens) {
        return jsonReject(licenseKey, gwAccessKeyReceived, license.bucket, 403, "AccessDenied", "HMAC tokens are disabled.", "HMAC_TOKENS_DISABLED", "medium", licenseCorsOrigins);
    }

    const tokenPayload = {
        k: cleanObjectKey,
        m: requestedMethod,
        iat: nowSec,
        exp: expSec,
        jti
    };
    if (singleUse) tokenPayload.su = 1;
    if (ipBind) tokenPayload.ip = ipBind;
    if (disposition) tokenPayload.cd = disposition;
    if (contentTypeOverride) tokenPayload.ct = contentTypeOverride;
    if (correlationId) tokenPayload.cid = correlationId;

    const token = await mintCloakedToken(licenseGatewayAccessKey, licenseGatewaySecretKey, tokenPayload, requestedMode);
    const routePrefix = bodyObj?.short_prefix === "s" ? "/s/" : "/dl/";
    const publicOrigin = `${url.protocol}//${url.host}`;
    const presignedUrl = `${publicOrigin}${routePrefix}${token}`;

    const durationMs = Date.now() - startMs;
    const authMeta = {
        mode: isBearer ? "presign_mint_bearer" : "presign_mint_sigv4",
        tokenJti: jti,
        correlationId,
        singleUse,
        ipBound: ipBind || null
    };

    const logEntry = buildLogEntry({
        licenseKey,
        gwHost: configuredGatewayHost,
        sourceIP,
        country,
        city,
        asn,
        asOrganization,
        userAgent,
        gwAccessKey: gwAccessKeyReceived,
        method,
        s3Operation,
        path: simulatedTargetPath,
        bucket: license.bucket,
        contentLength: 0,
        status: 200,
        durationMs,
        authMeta,
        securityDecision: undefined
    });
    if (env.R2_GATEWAY && ctx?.waitUntil) {
        ctx.waitUntil(writeLog(env, licenseKey, logEntry));
    }

    const respHeaders = new Headers({
        "Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Server": "s3gw"
    });
    applyCorsHeaders(respHeaders, request, licenseCorsOrigins);

    return new Response(JSON.stringify({
        url: presignedUrl,
        token,
        mode: requestedMode,
        method: requestedMethod,
        expires_in: effectiveTtl,
        expires_at: new Date(expSec * 1000).toISOString(),
        single_use: singleUse,
        ip_bind: ipBind || null,
        jti,
        correlation_id: correlationId || null
    }), { status: 200, headers: respHeaders });
}

async function handleCloakedTokenRequest({
    request, env, ctx, url, rawTargetPath, startMs, configuredGatewayHost, corsAllowedOrigins,
    sourceIP, method, contentLength, userAgent, country, city, asn, asOrganization
}) {
    const prefixLen = rawTargetPath.startsWith("/dl/") ? 4 : 3;
    const rawToken = rawTargetPath.slice(prefixLen).split("/")[0].trim();

    const rejectToken = (logLicenseKey, gwKeyUsed, bucketForLog, loggedPath, opType, status, code, message, blockReason, riskLevel = "high", policyCorsOrigins = corsAllowedOrigins, authMeta = { mode: "cloaked_token" }) => {
        const durationMs = Date.now() - startMs;
        const logEntry = buildLogEntry({
            licenseKey: logLicenseKey,
            gwHost: configuredGatewayHost,
            sourceIP,
            country,
            city,
            asn,
            asOrganization,
            userAgent,
            gwAccessKey: gwKeyUsed,
            method,
            s3Operation: opType,
            path: loggedPath,
            bucket: bucketForLog || "unknown",
            contentLength,
            status,
            durationMs,
            authMeta,
            securityDecision: { allowed: false, status, code, message, blockReason, riskLevel }
        });
        if (env.R2_GATEWAY && ctx?.waitUntil) {
            ctx.waitUntil(writeLog(env, logLicenseKey, logEntry));
        }
        return errorResponse(status, code, message, configuredGatewayHost, request, policyCorsOrigins);
    };

    const parsedOuter = extractAccessKeyFromCloakedToken(rawToken);
    if (!parsedOuter) {
        return rejectToken("_unauthenticated", "INVALID", "unknown", "/dl/_invalid_token", "getObject", 403, "AccessDenied", "Invalid or malformed download link.", "MALFORMED_CLOAKED_TOKEN", "medium");
    }

    const gwAccessKeyReceived = parsedOuter.accessKey;
    const licenseKey = gwAccessKeyReceived;

    const [license, keyQuarantine, ipQuarantine] = await Promise.all([
        getCachedKV(env, licenseKey),
        getCachedKV(env, `quarantine:${licenseKey}`),
        sourceIP ? getCachedKV(env, `quarantine:${licenseKey}:${sourceIP}`) : Promise.resolve(null)
    ]);
    const quarantine = keyQuarantine || ipQuarantine;

    if (!license) {
        return rejectToken("_unauthenticated", gwAccessKeyReceived, "unknown", "/dl/_unknown_license", "getObject", 403, "InvalidAccessKeyId", "Invalid link credentials.", "UNKNOWN_LICENSE_KEY", "high");
    }

    const licenseCorsOrigins = parseAllowedOrigins(
        license.security_policy?.allowed_origins ||
        license.securityPolicy?.allowedOrigins ||
        license.cors_allowed_origins ||
        env.CORS_ALLOWED_ORIGINS
    );

    if (!license.activated || new Date(license.expires_at) < new Date() || !license.gateway?.enabled) {
        return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, `/${license.bucket}/_inactive`, "getObject", 403, "AccessDenied", "Gateway license is inactive or expired.", "LICENSE_INACTIVE_OR_EXPIRED", "medium", licenseCorsOrigins);
    }

    const presignedCfg = resolvePresignedConfig(license);
    if (!presignedCfg.enabled) {
        return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, `/${license.bucket}/_disabled`, "getObject", 403, "AccessDenied", "Presigned URLs are disabled.", "PRESIGNED_URLS_DISABLED", "high", licenseCorsOrigins);
    }

    const licenseGatewayAccessKey = license.gateway.access_key || license.gateway.accessKey;
    const licenseGatewaySecretKey = license.gateway.secret_key || license.gateway.secretKey;
    if (licenseGatewayAccessKey !== gwAccessKeyReceived) {
        return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, `/${license.bucket}/_mismatch`, "getObject", 403, "InvalidAccessKeyId", "Access key mismatch.", "ACCESS_KEY_MISMATCH", "high", licenseCorsOrigins);
    }

    const verified = await verifyAndDecodeCloakedToken(parsedOuter, licenseGatewaySecretKey, presignedCfg);
    if (!verified.valid) {
        const isExpired = verified.reason === "TokenExpired";
        const p = verified.payload;
        const partialKey = p?.k ? `/${license.bucket}/${String(p.k).replace(/^\/+/, "")}` : `/${license.bucket}/_unverified_token`;
        return rejectToken(
            licenseKey,
            gwAccessKeyReceived,
            license.bucket,
            partialKey,
            "getObject",
            403,
            "AccessDenied",
            isExpired ? "Download link has expired." : "Invalid or tampered download link.",
            isExpired ? "PRESIGNED_URL_EXPIRED" : `CLOAKED_TOKEN_${String(verified.reason || "INVALID").toUpperCase()}`,
            isExpired ? "low" : "high",
            licenseCorsOrigins,
            {
                mode: parsedOuter.version === "v1e" ? "cloaked_token_encrypted" : "cloaked_token_hmac",
                tokenJti: p?.jti || null,
                correlationId: p?.cid || null
            }
        );
    }

    const payload = verified.payload;
    const singleUse = Boolean(payload.su === 1 || payload.su === true || presignedCfg.enforceSingleUse);
    const authMeta = {
        mode: verified.mode,
        tokenJti: payload.jti || null,
        correlationId: payload.cid || null,
        singleUse,
        ipBound: payload.ip || null
    };

    const { segments: keySegments, hasTraversal } = normalizeAndInspectPath(payload.k);
    if (hasTraversal || keySegments.length === 0) {
        return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, `/${license.bucket}/_traversal`, "getObject", 400, "InvalidURI", "Invalid object key in token.", "PATH_TRAVERSAL_DETECTED", "critical", licenseCorsOrigins, authMeta);
    }

    const cleanSegments = (keySegments[0] === license.bucket && keySegments.length > 1)
        ? keySegments.slice(1)
        : keySegments;
    const backendTargetPath = `/${license.bucket}/${cleanSegments.join("/")}`;
    const tokenMethod = String(payload.m || "GET").toUpperCase();
    const methodAllowedByToken = method === tokenMethod || (tokenMethod === "GET" && method === "HEAD");
    const s3Operation = method === "PUT" ? "putObject" : (method === "HEAD" ? "headObject" : "getObject");

    if (!methodAllowedByToken || !presignedCfg.allowedMethods.includes(method)) {
        return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, backendTargetPath, s3Operation, 403, "AccessDenied", `HTTP method '${method}' is not permitted for this link.`, "PRESIGNED_METHOD_NOT_ALLOWED", "high", licenseCorsOrigins, authMeta);
    }

    if (payload.ip) {
        if (!sourceIP || !ipMatchesCidrOrExact(sourceIP, payload.ip)) {
            return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, backendTargetPath, s3Operation, 403, "AccessDenied", "Access denied: client IP does not match link binding.", "TOKEN_IP_MISMATCH", "high", licenseCorsOrigins, authMeta);
        }
    }

    if (quarantine) {
        return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, backendTargetPath, s3Operation, 429, "SlowDown", `S3GW Exfiltration Guard: Access key is quarantined (${quarantine.reason || "Quota exceeded"}).`, "QUARANTINED_BY_QUOTA", "high", licenseCorsOrigins, authMeta);
    }

    const secDecision = checkSecurityPolicy(env, request, url, backendTargetPath, license, s3Operation, sourceIP, country, asn, userAgent);
    if (!secDecision.allowed) {
        return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, backendTargetPath, s3Operation, secDecision.status || 403, secDecision.code || "AccessDenied", secDecision.message, secDecision.blockReason || "SECURITY_POLICY_VIOLATION", secDecision.riskLevel || "high", licenseCorsOrigins, authMeta);
    }

    const disableDlpKv = isDlpKvWritesDisabled(env, license);

    if (singleUse && method !== "HEAD") {
        if (!payload.jti) {
            return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, backendTargetPath, s3Operation, 403, "AccessDenied", "Single-use policy requires a token JTI.", "MISSING_SINGLE_USE_JTI", "high", licenseCorsOrigins, authMeta);
        }
        const alreadyConsumed = await checkSingleUseTokenConsumed(env, licenseKey, payload.jti, disableDlpKv);
        if (alreadyConsumed) {
            return rejectToken(licenseKey, gwAccessKeyReceived, license.bucket, backendTargetPath, s3Operation, 403, "AccessDenied", "This single-use link has already been used.", "SINGLE_USE_TOKEN_ALREADY_CONSUMED", "high", licenseCorsOrigins, authMeta);
        }
    }

    const backendResp = await forwardToBackend(request, url, backendTargetPath, license, env, null, {
        stripAllQuery: true
    });
    const durationMs = Date.now() - startMs;

    const respBytes = parseInt(backendResp.headers.get("Content-Length") || "0", 10);
    const actualBytes = (method === "GET" || s3Operation === "getObject") ? respBytes : contentLength;

    if (singleUse && method !== "HEAD" && (backendResp.ok || backendResp.status === 206 || backendResp.status === 304)) {
        const remTtl = Math.max(60, Number(payload.exp) - Math.floor(Date.now() / 1000));
        const markPromise = markSingleUseTokenConsumed(env, licenseKey, payload.jti, remTtl, disableDlpKv);
        if (ctx?.waitUntil) ctx.waitUntil(markPromise);
        else await markPromise;
    }

    if (!disableDlpKv && (backendResp.ok || backendResp.status === 206 || backendResp.status === 304)) {
        if (ctx?.waitUntil) {
            ctx.waitUntil(trackDlpQuotasAndQuarantine(env, licenseKey, sourceIP, license, method, s3Operation, actualBytes, 1));
        }
    }

    const logEntry = buildLogEntry({
        licenseKey,
        gwHost: configuredGatewayHost,
        sourceIP,
        country,
        city,
        asn,
        asOrganization,
        userAgent,
        gwAccessKey: gwAccessKeyReceived,
        method,
        s3Operation,
        path: backendTargetPath,
        bucket: license.bucket,
        contentLength: actualBytes,
        status: backendResp.status,
        durationMs,
        authMeta,
        securityDecision: undefined
    });
    if (env.R2_GATEWAY && ctx?.waitUntil) {
        ctx.waitUntil(writeLog(env, licenseKey, logEntry));
    }

    const respHeaders = sanitizeBackendResponseHeaders(backendResp.headers, license, {
        fullCloak: true,
        contentDisposition: payload.cd,
        contentType: payload.ct
    });
    applyCorsHeaders(respHeaders, request, licenseCorsOrigins);
    if (!backendResp.ok) {
        respHeaders.set("Cache-Control", "no-transform, no-store");
    }

    return new Response(backendResp.body, {
        status: backendResp.status,
        statusText: backendResp.statusText,
        headers: respHeaders,
    });
}

function sanitizeBackendResponseHeaders(backendHeaders, license, overrides = {}) {
    const out = new Headers(backendHeaders);
    const shouldCloak = license?.gateway?.cloak_backend_headers !== false && license?.gateway?.cloakBackendHeaders !== false;
    if (shouldCloak) {
        const toDelete = [];
        for (const [k] of out.entries()) {
            const lower = k.toLowerCase();
            if (overrides.fullCloak) {
                if (CLOAKED_EXACT_HEADERS.has(lower) || CLOAKED_HEADER_PREFIXES.some(p => lower.startsWith(p))) {
                    toDelete.push(k);
                }
            } else {
                if (
                    CLOAKED_EXACT_HEADERS.has(lower) ||
                    lower === "x-amz-id-2" ||
                    lower === "x-amz-request-id" ||
                    lower.startsWith("x-scw-") ||
                    lower.startsWith("x-ovh-") ||
                    lower.startsWith("x-rgw-")
                ) {
                    toDelete.push(k);
                }
            }
        }
        for (const k of toDelete) {
            out.delete(k);
        }
        out.set("Server", "s3gw");
    }
    if (overrides.contentDisposition) {
        out.set("Content-Disposition", overrides.contentDisposition);
    }
    if (overrides.contentType) {
        out.set("Content-Type", overrides.contentType);
    }
    return out;
}

function stripSigV4QueryParams(searchParams) {
    const clean = new URLSearchParams();
    for (const [k, v] of searchParams.entries()) {
        if (!PRESIGN_SIGV4_QUERY_KEYS.has(k.toLowerCase())) {
            clean.append(k, v);
        }
    }
    const str = clean.toString();
    return str ? `?${str}` : "";
}

function extractAccessKeyFromQuery(searchParams) {
    const cred = searchParams.get("X-Amz-Credential") || searchParams.get("x-amz-credential") || "";
    const slashIdx = cred.indexOf("/");
    return slashIdx > 0 ? cred.slice(0, slashIdx) : "-";
}

async function verifyAwsSigV4PresignedQuery(request, gatewaySecret, url, maxTtlSeconds = DEFAULT_MAX_PRESIGN_TTL_SECONDS) {
    try {
        if (!gatewaySecret) return { valid: false, reason: "MissingSecret" };
        const sp = url.searchParams;
        const algorithm = sp.get("X-Amz-Algorithm") || sp.get("x-amz-algorithm") || "";
        const credentialScope = sp.get("X-Amz-Credential") || sp.get("x-amz-credential") || "";
        const amzDate = (sp.get("X-Amz-Date") || sp.get("x-amz-date") || "").trim();
        const expiresStr = (sp.get("X-Amz-Expires") || sp.get("x-amz-expires") || "").trim();
        const signedHeadersStr = (sp.get("X-Amz-SignedHeaders") || sp.get("x-amz-signedheaders") || "").trim();
        const receivedSigHex = (sp.get("X-Amz-Signature") || sp.get("x-amz-signature") || "").trim().toLowerCase();

        if (algorithm !== "AWS4-HMAC-SHA256" || !credentialScope || !amzDate || !expiresStr || !signedHeadersStr || !receivedSigHex) {
            return { valid: false, reason: "MalformedPresignedQuery" };
        }

        const receivedSigBytes = hexToBytes(receivedSigHex);
        if (!receivedSigBytes || receivedSigBytes.byteLength !== 32) {
            return { valid: false, reason: "MalformedSignature" };
        }

        const credParts = credentialScope.split("/");
        if (credParts.length !== 5 || credParts[4] !== "aws4_request") {
            return { valid: false, reason: "InvalidScope" };
        }

        const dateStamp = credParts[1];
        const region = credParts[2];
        const service = credParts[3];

        if (!/^\d{8}$/.test(dateStamp) || amzDate.slice(0, 8) !== dateStamp) {
            return { valid: false, reason: "RequestTimeTooSkewed" };
        }

        const expiresSec = parseInt(expiresStr, 10);
        if (isNaN(expiresSec) || expiresSec < 1 || expiresSec > maxTtlSeconds) {
            return { valid: false, reason: "RequestTimeTooSkewed" };
        }

        const reqTimeMs = parseAmzDateMs(amzDate, null);
        const nowMs = Date.now();
        if (isNaN(reqTimeMs) || reqTimeMs - nowMs > MAX_SIGV4_CLOCK_SKEW_MS) {
            return { valid: false, reason: "RequestTimeTooSkewed" };
        }
        if (nowMs > reqTimeMs + expiresSec * 1000) {
            return { valid: false, reason: "RequestExpired" };
        }

        const queryForSigning = new URLSearchParams();
        for (const [k, v] of sp.entries()) {
            if (k.toLowerCase() !== "x-amz-signature") {
                queryForSigning.append(k, v);
            }
        }
        const canonicalQueryString = buildCanonicalQueryString(queryForSigning);
        const signedHeaders = signedHeadersStr.split(";");
        const scope = `${dateStamp}/${region}/${service}/aws4_request`;
        const signingCryptoKey = await getCachedSigningCryptoKey(gatewaySecret, dateStamp, region, service);

        const getNormHeader = (h) => {
            if (h === "host") return url.host;
            const raw = request.headers.get(h);
            if (raw === null || raw === undefined) return "";
            return raw.trim().replace(/\s+/g, " ");
        };

        const canPath = url.pathname.split("/").map(seg => {
            try { return uriEncode(decodeURIComponent(seg)); } catch (e) { return uriEncode(seg); }
        }).join("/");
        const pathCandidates = Array.from(new Set([url.pathname, canPath]));
        const canHeaders = signedHeaders.map(h => `${h}:${getNormHeader(h)}`).join("\n") + "\n";

        for (const p of pathCandidates) {
            const canonicalRequest = [
                request.method,
                p,
                canonicalQueryString,
                canHeaders,
                signedHeadersStr,
                "UNSIGNED-PAYLOAD"
            ].join("\n");

            const reqHash = await sha256Hex(canonicalRequest);
            const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, reqHash].join("\n");
            const computedSigBytes = new Uint8Array(
                await crypto.subtle.sign("HMAC", signingCryptoKey, enc(stringToSign))
            );
            if (timingSafeEqualBytes(computedSigBytes, receivedSigBytes)) {
                return { valid: true };
            }
        }

        return { valid: false, reason: "SignatureDoesNotMatch" };
    } catch (_) {
        return { valid: false, reason: "VerifyException" };
    }
}

function validateCopySourceHeader(rawCopySource, allowedBucket) {
    const decoded = fullyDecodeURIComponent(String(rawCopySource || "").trim());
    const withoutQuery = decoded.split("?")[0].trim();
    if (!withoutQuery) {
        return { valid: false, sourceBucket: "", blockReason: "INVALID_COPY_SOURCE", message: "Invalid x-amz-copy-source header." };
    }
    const { segments, hasTraversal } = normalizeAndInspectPath(withoutQuery);
    if (hasTraversal || segments.length < 2) {
        return { valid: false, sourceBucket: segments[0] || "", blockReason: "INVALID_COPY_SOURCE", message: "Invalid or traversal x-amz-copy-source path." };
    }
    const sourceBucket = segments[0];
    if (sourceBucket !== allowedBucket) {
        return {
            valid: false,
            sourceBucket,
            blockReason: "CROSS_BUCKET_COPY_FORBIDDEN",
            message: `Cross-bucket copy from '${sourceBucket}' is forbidden by your S3GW license.`
        };
    }
    return { valid: true, sourceBucket };
}

function countDeleteObjectsInXml(xmlText) {
    if (!xmlText) return 1;
    const objectMatches = xmlText.match(/<(?:[a-zA-Z0-9_-]+:)?Object[\s>]/g);
    if (objectMatches && objectMatches.length > 0) {
        return objectMatches.length;
    }
    const keyMatches = xmlText.match(/<(?:[a-zA-Z0-9_-]+:)?Key[\s>]/g);
    return keyMatches && keyMatches.length > 0 ? keyMatches.length : 1;
}

function parseAmzDateMs(amzDateStr, fallbackDateHeader) {
    if (amzDateStr && /^\d{8}T\d{6}Z$/.test(amzDateStr)) {
        const y = parseInt(amzDateStr.slice(0, 4), 10);
        const m = parseInt(amzDateStr.slice(4, 6), 10) - 1;
        const d = parseInt(amzDateStr.slice(6, 8), 10);
        const hh = parseInt(amzDateStr.slice(9, 11), 10);
        const mm = parseInt(amzDateStr.slice(11, 13), 10);
        const ss = parseInt(amzDateStr.slice(13, 15), 10);
        return Date.UTC(y, m, d, hh, mm, ss);
    }
    if (fallbackDateHeader) {
        const parsed = Date.parse(fallbackDateHeader);
        if (!isNaN(parsed)) return parsed;
    }
    return NaN;
}

function hexToBytes(hexStr) {
    if (!hexStr || hexStr.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hexStr)) return null;
    const out = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function timingSafeEqualBytes(a, b) {
    if (!a || !b || a.byteLength !== b.byteLength) return false;
    if (typeof crypto !== "undefined" && crypto.subtle && typeof crypto.subtle.timingSafeEqual === "function") {
        try {
            return crypto.subtle.timingSafeEqual(a, b);
        } catch (_) {
        }
    }
    let diff = 0;
    for (let i = 0; i < a.byteLength; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

function buildCanonicalQueryString(searchParams) {
    return [...searchParams.entries()]
        .map(([k, v]) => [uriEncode(k), uriEncode(v)])
        .sort(([ak, av], [bk, bv]) => (ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0))
        .map(([ek, ev]) => `${ek}=${ev}`)
        .join("&");
}

async function verifyAwsSigV4(request, gatewaySecret, url) {
    try {
        if (!gatewaySecret) return { valid: false, reason: "MissingSecret" };
        const authHeader = request.headers.get("Authorization") || "";
        const amzDate = (request.headers.get("X-Amz-Date") || "").trim();
        const httpDate = (request.headers.get("Date") || "").trim();

        const credMatch = authHeader.match(/Credential=([^,\s]+)/);
        const signedMatch = authHeader.match(/SignedHeaders=([^,\s]+)/);
        const sigMatch = authHeader.match(/Signature=([a-fA-F0-9]{64})/);

        if (!credMatch || !signedMatch || !sigMatch) {
            return { valid: false, reason: "MalformedAuthHeader" };
        }

        const credentialScope = credMatch[1];
        const signedHeadersStr = signedMatch[1];
        const receivedSigHex = sigMatch[1].toLowerCase();
        const receivedSigBytes = hexToBytes(receivedSigHex);
        if (!receivedSigBytes) return { valid: false, reason: "MalformedSignature" };

        const credParts = credentialScope.split("/");
        if (credParts.length !== 5 || credParts[4] !== "aws4_request") {
            return { valid: false, reason: "InvalidScope" };
        }

        const dateStamp = credParts[1];
        const region = credParts[2];
        const service = credParts[3];

        if (!/^\d{8}$/.test(dateStamp)) {
            return { valid: false, reason: "InvalidDateStamp" };
        }

        if (amzDate && amzDate.slice(0, 8) !== dateStamp) {
            return { valid: false, reason: "RequestTimeTooSkewed" };
        }

        const reqTimeMs = parseAmzDateMs(amzDate, httpDate);
        if (isNaN(reqTimeMs) || Math.abs(Date.now() - reqTimeMs) > MAX_SIGV4_CLOCK_SKEW_MS) {
            return { valid: false, reason: "RequestTimeTooSkewed" };
        }

        const canonicalQueryString = buildCanonicalQueryString(url.searchParams);

        const payloadHash = request.headers.get("X-Amz-Content-Sha256") || "UNSIGNED-PAYLOAD";
        const signedHeaders = signedHeadersStr.split(";");
        const scope = `${dateStamp}/${region}/${service}/aws4_request`;

        const signingCryptoKey = await getCachedSigningCryptoKey(gatewaySecret, dateStamp, region, service);

        const getNormHeader = (h, overrideVal) => {
            if (overrideVal !== undefined) return overrideVal;
            const raw = request.headers.get(h);
            if (raw === null || raw === undefined) return "";
            return raw.trim().replace(/\s+/g, " ");
        };

        const canPath = url.pathname.split("/").map(seg => {
            try { return uriEncode(decodeURIComponent(seg)); } catch (e) { return uriEncode(seg); }
        }).join("/");
        const pathCandidates = Array.from(new Set([url.pathname, canPath]));

        const aeVariations = signedHeaders.includes("accept-encoding")
            ? Array.from(new Set([getNormHeader("accept-encoding"), "gzip", "identity", "gzip, deflate", ""]))
            : [undefined];
        const connVariations = signedHeaders.includes("connection")
            ? Array.from(new Set([getNormHeader("connection"), "keep-alive", "close", ""]))
            : [undefined];

        const effectiveDateStr = amzDate || httpDate;
        let attempts = 0;

        for (const p of pathCandidates) {
            for (const ae of aeVariations) {
                for (const conn of connVariations) {
                    if (++attempts > 16) break;
                    const overrides = {};
                    if (ae !== undefined) overrides["accept-encoding"] = ae;
                    if (conn !== undefined) overrides["connection"] = conn;

                    const canHeaders = signedHeaders
                        .map(h => `${h}:${getNormHeader(h, overrides[h])}`)
                        .join("\n") + "\n";

                    const canonicalRequest = [
                        request.method,
                        p,
                        canonicalQueryString,
                        canHeaders,
                        signedHeadersStr,
                        payloadHash,
                    ].join("\n");

                    const reqHash = await sha256Hex(canonicalRequest);
                    const stringToSign = ["AWS4-HMAC-SHA256", effectiveDateStr, scope, reqHash].join("\n");
                    const computedSigBytes = new Uint8Array(
                        await crypto.subtle.sign("HMAC", signingCryptoKey, enc(stringToSign))
                    );

                    if (timingSafeEqualBytes(computedSigBytes, receivedSigBytes)) {
                        return { valid: true };
                    }
                }
            }
        }

        return { valid: false, reason: "SignatureDoesNotMatch" };
    } catch (e) {
        console.error("SigV4 verify error:", e.message);
        return { valid: false, reason: "VerifyException" };
    }
}

async function deriveSigningKey(secret, dateStamp, region, service) {
    const kDate = await hmacRaw(enc("AWS4" + secret), dateStamp);
    const kRegion = await hmacRaw(kDate, region);
    const kService = await hmacRaw(kRegion, service);
    const kSigning = await hmacRaw(kService, "aws4_request");
    return kSigning;
}

async function getCachedSigningCryptoKey(secret, dateStamp, region, service) {
    const cacheKey = `${dateStamp}:${region}:${service}:${secret}`;
    const now = Date.now();
    if (signingKeyCache.has(cacheKey)) {
        const entry = signingKeyCache.get(cacheKey);
        if (now - entry.timestamp < SIGNING_KEY_TTL_MS) {
            signingKeyCache.delete(cacheKey);
            signingKeyCache.set(cacheKey, entry);
            return entry.cryptoKey;
        }
        signingKeyCache.delete(cacheKey);
    }
    const rawSigningKey = await deriveSigningKey(secret, dateStamp, region, service);
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        rawSigningKey,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    setBoundedMap(signingKeyCache, MAX_SIGNING_KEY_CACHE_ENTRIES, cacheKey, {
        cryptoKey,
        timestamp: now
    });
    return cryptoKey;
}

async function hmacRaw(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw", typeof key === "string" ? enc(key) : key,
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, enc(data)));
}

async function hmacHex(key, data) {
    const raw = await hmacRaw(key, data);
    return Array.from(raw).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function signWithCryptoKeyHex(cryptoKey, data) {
    const raw = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, enc(data)));
    return Array.from(raw).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", enc(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

const enc = (s) => new TextEncoder().encode(s);

async function forwardToBackend(request, originalUrl, targetPath, license, env, preReadBodyBuffer = null, options = {}) {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "").slice(0, 15) + "Z";
    const dateStamp = amzDate.slice(0, 8);
    const region = (license.region || "auto").trim().toLowerCase();
    const service = "s3";

    const payloadHash = request.headers.get("X-Amz-Content-Sha256") || "UNSIGNED-PAYLOAD";

    let backendEndpoint = (license.endpoint || "").trim().replace(/\/+$/, "");
    let scheme = "https://";
    if (backendEndpoint.startsWith("http://")) {
        scheme = "http://";
        backendEndpoint = backendEndpoint.slice(7);
    } else if (backendEndpoint.startsWith("https://")) {
        scheme = "https://";
        backendEndpoint = backendEndpoint.slice(8);
    }

    let backendPath = targetPath;
    const pathParts = targetPath.split("/").filter(p => p.length > 0);
    const bucketName = pathParts.length > 0 ? pathParts[0] : "";

    const VIRTUAL_HOST_PROVIDERS = [
        "amazonaws.com",
        "cloud.ovh.net",
        "scw.cloud",
        "backblazeb2.com",
        "wasabisys.com",
        "leviia.com",
        "r2.cloudflarestorage.com",
        "cloud-object-storage.appdomain.cloud",
        "objectstorage.softlayer.net",
        "aliyuncs.com",
        "myqcloud.com",
        "digitaloceanspaces.com",
        "linodeobjects.com",
        "exoscale.com",
        "hetzner.com",
        "outscale.com",
        "oraclecloud.com"
    ];

    const preferVirtualHost = license.forceVirtualHost ?? VIRTUAL_HOST_PROVIDERS.some(domain => backendEndpoint.toLowerCase().includes(domain));
    const forcePathStyle = license.forcePathStyle === true;

    if (bucketName && preferVirtualHost && !forcePathStyle) {
        if (!backendEndpoint.toLowerCase().startsWith(bucketName.toLowerCase() + ".")) {
            backendEndpoint = `${bucketName}.${backendEndpoint}`;
        }
        const prefixRegex = new RegExp(`^/+${bucketName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=/|$)`);
        backendPath = targetPath.replace(prefixRegex, "");
        if (!backendPath.startsWith("/")) backendPath = "/" + backendPath;
    }

    const backendBase = `${scheme}${backendEndpoint}`;
    const backendHost = backendEndpoint;

    const effectiveQuery = options.stripAllQuery
        ? ""
        : (options.stripSigV4Query ? stripSigV4QueryParams(originalUrl.searchParams) : originalUrl.search);

    const backendUrl = new URL(backendPath + effectiveQuery, backendBase);

    const cleanHeaders = new Headers(request.headers);
    cleanHeaders.delete("Authorization");
    cleanHeaders.delete("CF-Connecting-IP");
    cleanHeaders.delete("CF-Ray");
    cleanHeaders.delete("CF-Visitor");
    cleanHeaders.delete("x-amz-security-token");
    cleanHeaders.set("Host", backendHost);
    cleanHeaders.set("X-Amz-Date", amzDate);
    cleanHeaders.set("User-Agent", "s3gw/1.1.1");

    let bodyToForward = (["GET", "HEAD", "DELETE"].includes(request.method) ? null : (preReadBodyBuffer !== null ? preReadBodyBuffer : request.body));
    let actualPayloadHash = payloadHash;
    if (bodyToForward === null && (actualPayloadHash === "UNSIGNED-PAYLOAD" || !actualPayloadHash)) {
        actualPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }

    const isChunkedSigning = payloadHash.startsWith("STREAMING-") ||
        (request.headers.get("content-encoding") || "").includes("aws-chunked") ||
        (request.headers.get("x-amz-content-encoding") || "").includes("aws-chunked");

    if (isChunkedSigning && bodyToForward && typeof bodyToForward.pipeThrough === "function") {
        actualPayloadHash = "UNSIGNED-PAYLOAD";
        if (cleanHeaders.has("x-amz-decoded-content-length")) {
            cleanHeaders.set("Content-Length", cleanHeaders.get("x-amz-decoded-content-length"));
            cleanHeaders.delete("x-amz-decoded-content-length");
        }
        const ce = cleanHeaders.get("content-encoding");
        if (ce) {
            const newCe = ce.split(",").map(s => s.trim()).filter(s => s !== "aws-chunked").join(", ");
            if (newCe) cleanHeaders.set("content-encoding", newCe);
            else cleanHeaders.delete("content-encoding");
        }
        const xce = cleanHeaders.get("x-amz-content-encoding");
        if (xce) {
            const newXce = xce.split(",").map(s => s.trim()).filter(s => s !== "aws-chunked").join(", ");
            if (newXce) cleanHeaders.set("x-amz-content-encoding", newXce);
            else cleanHeaders.delete("x-amz-content-encoding");
        }
        bodyToForward = bodyToForward.pipeThrough(createAwsChunkedDecoderStream());
    }

    cleanHeaders.set("X-Amz-Content-Sha256", actualPayloadHash);

    const headersToSign = new Set(["host", "x-amz-content-sha256", "x-amz-date"]);
    const optionalHeaders = [
        "content-type", "content-md5", "content-disposition", "content-encoding", "content-language",
        "cache-control", "expires", "range", "if-match", "if-none-match", "if-modified-since",
        "if-unmodified-since"
    ];

    for (const [key] of cleanHeaders.entries()) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith("x-amz-") || optionalHeaders.includes(lowerKey)) {
            headersToSign.add(lowerKey);
        }
    }

    const signedHeaderNames = Array.from(headersToSign).sort();

    const canonicalHeaders = signedHeaderNames
        .map(h => `${h}:${(cleanHeaders.get(h) || "").trim().replace(/\s+/g, " ")}`)
        .join("\n") + "\n";

    const canonicalQueryString = buildCanonicalQueryString(backendUrl.searchParams);

    const canBackendPath = backendUrl.pathname.split("/").map(seg => {
        try { return uriEncode(decodeURIComponent(seg)); } catch (e) { return uriEncode(seg); }
    }).join("/") || "/";

    const canonicalRequest = [
        request.method,
        canBackendPath,
        canonicalQueryString,
        canonicalHeaders,
        signedHeaderNames.join(";"),
        actualPayloadHash,
    ].join("\n");

    const scope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = [
        "AWS4-HMAC-SHA256",
        amzDate,
        scope,
        await sha256Hex(canonicalRequest),
    ].join("\n");

    const realSecretKey = license.secretKey || license.secret_key;
    const realAccessKey = license.accessKey || license.access_key;

    const signingCryptoKey = await getCachedSigningCryptoKey(realSecretKey, dateStamp, region, service);
    const signature = await signWithCryptoKeyHex(signingCryptoKey, stringToSign);

    cleanHeaders.set("Authorization",
        `AWS4-HMAC-SHA256 Credential=${realAccessKey}/${scope}, ` +
        `SignedHeaders=${signedHeaderNames.join(";")}, Signature=${signature}`
    );

    const finalOutboundUrl = `${backendBase}${canBackendPath}${canonicalQueryString ? "?" + canonicalQueryString : ""}`;
    return fetch(finalOutboundUrl, {
        method: request.method,
        headers: cleanHeaders,
        body: bodyToForward,
    });
}

function decideShouldLog(method, s3Operation, contentLength) {
    if (!LOGGABLE_METHODS.has(method)) return false;

    if (method === "POST" && !LOGGABLE_POST_ACTIONS.has(s3Operation)) return false;

    return true;
}

function resolveS3Operation(method, path, queryString, headers = null) {
    const params = new URLSearchParams(queryString.replace("?", ""));
    const hasCopySourceHeader = Boolean(headers && typeof headers.get === "function" && headers.get("x-amz-copy-source"));

    if (method === "GET") {
        const segments = path.split("/").filter(Boolean);
        const isObject = segments.length > 1;
        if (segments.length === 0) return "listBuckets";
        if (params.has("tagging")) return isObject ? "getObjectTagging" : "getBucketTagging";
        if (params.has("acl")) return isObject ? "getObjectAcl" : "getBucketAcl";
        if (params.has("versioning")) return "getBucketVersioning";
        if (params.has("lifecycle")) return "getBucketLifecycle";
        if (params.has("policy")) return "getBucketPolicy";
        if (params.has("cors")) return "getBucketCors";
        if (params.has("website")) return "getBucketWebsite";
        if (params.has("replication")) return "getBucketReplication";
        if (params.has("object-lock")) return "getObjectLockConfiguration";
        if (params.has("logging")) return "getBucketLogging";
        if (params.has("encryption")) return "getBucketEncryption";
        if (params.has("notification")) return "getBucketNotification";
        if (params.has("publicAccessBlock")) return "getPublicAccessBlock";
        if (params.has("ownershipControls")) return "getOwnershipControls";

        if (params.has("list-type") || params.has("delimiter") || params.has("prefix") || segments.length <= 1) return "listObjects";
        return "getObject";
    }

    if (method === "DELETE") {
        const segments = path.split("/").filter(Boolean);
        const isObject = segments.length > 1;
        if (params.has("uploadId")) return "abortMultipartUpload";
        if (params.has("tagging")) return isObject ? "deleteObjectTagging" : "deleteBucketTagging";
        if (params.has("lifecycle")) return "deleteBucketLifecycle";
        if (params.has("policy")) return "deleteBucketPolicy";
        if (params.has("cors")) return "deleteBucketCors";
        if (params.has("website")) return "deleteBucketWebsite";
        if (params.has("replication")) return "deleteBucketReplication";
        if (params.has("encryption")) return "deleteBucketEncryption";
        if (params.has("publicAccessBlock")) return "deletePublicAccessBlock";
        if (params.has("ownershipControls")) return "deleteOwnershipControls";
        return isObject ? "deleteObject" : "deleteBucket";
    }

    if (method === "PUT") {
        const segments = path.split("/").filter(Boolean);
        const isObject = segments.length > 1;
        if (params.has("tagging")) return isObject ? "putObjectTagging" : "putBucketTagging";
        if (params.has("acl")) return isObject ? "putObjectAcl" : "putBucketAcl";
        if (params.has("versioning")) return "putBucketVersioning";
        if (params.has("lifecycle")) return "putBucketLifecycle";
        if (params.has("policy")) return "putBucketPolicy";
        if (params.has("cors")) return "putBucketCors";
        if (params.has("website")) return "putBucketWebsite";
        if (params.has("replication")) return "putBucketReplication";
        if (params.has("object-lock")) return "putObjectLockConfiguration";
        if (params.has("encryption")) return "putBucketEncryption";
        if (params.has("logging")) return "putBucketLogging";
        if (params.has("notification")) return "putBucketNotification";
        if (params.has("publicAccessBlock")) return "putPublicAccessBlock";
        if (params.has("ownershipControls")) return "putOwnershipControls";
        if (hasCopySourceHeader || params.has("copySource") || params.get("x-amz-copy-source")) return "copyObject";
        if (params.has("uploadId")) return "uploadPart";
        return "putObject";
    }

    if (method === "POST") {
        if (params.has("delete")) return "deleteObjects";
        if (params.has("restore")) return "restoreObject";
        if (params.has("uploads")) return "createMultipartUpload";
        if (params.has("uploadId")) return "completeMultipartUpload";
        return "postObject";
    }

    if (method === "HEAD") {
        const segments = path.split("/").filter(Boolean);
        return segments.length > 1 ? "headObject" : "headBucket";
    }

    if (method === "OPTIONS") {
        const segments = path.split("/").filter(Boolean);
        return segments.length > 1 ? "optionsObject" : "optionsBucket";
    }

    return `${method.toLowerCase()}Unknown`;
}

function parseIpv4ToBigInt(ipStr) {
    const parts = ipStr.split(".");
    if (parts.length !== 4) return null;
    let val = 0n;
    for (const p of parts) {
        if (!/^\d{1,3}$/.test(p)) return null;
        const n = Number(p);
        if (n < 0 || n > 255) return null;
        val = (val << 8n) | BigInt(n);
    }
    return val;
}

function parseIpAddress(rawIp) {
    if (!rawIp || typeof rawIp !== "string") return null;
    let ip = rawIp.trim();
    if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
    const zoneIdx = ip.indexOf("%");
    if (zoneIdx !== -1) ip = ip.slice(0, zoneIdx);

    if (ip.includes(":")) {
        let workIp = ip.toLowerCase();

        if (workIp.includes(".")) {
            const lastColon = workIp.lastIndexOf(":");
            const v4Part = workIp.slice(lastColon + 1);
            const v4Val = parseIpv4ToBigInt(v4Part);
            if (v4Val === null) return null;
            const highHex = Number((v4Val >> 16n) & 0xffffn).toString(16);
            const lowHex = Number(v4Val & 0xffffn).toString(16);
            workIp = `${workIp.slice(0, lastColon)}:${highHex}:${lowHex}`;
        }

        const dblColonParts = workIp.split("::");
        if (dblColonParts.length > 2) return null;

        const left = dblColonParts[0] ? dblColonParts[0].split(":") : [];
        const right = dblColonParts.length === 2 && dblColonParts[1] ? dblColonParts[1].split(":") : [];

        if (dblColonParts.length === 1 && left.length !== 8) return null;
        if (dblColonParts.length === 2 && left.length + right.length > 7) return null;

        const missingZeros = 8 - (left.length + right.length);
        const groups = [...left, ...Array(missingZeros).fill("0"), ...right];
        if (groups.length !== 8) return null;

        let val = 0n;
        for (const g of groups) {
            if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
            val = (val << 16n) | BigInt(parseInt(g, 16));
        }

        const isV4Mapped = (val >> 32n) === 0xffffn;
        return {
            version: 6,
            value: val,
            bits: 128n,
            mappedV4: isV4Mapped ? (val & 0xffffffffn) : null
        };
    }

    const v4 = parseIpv4ToBigInt(ip);
    if (v4 === null) return null;
    return {
        version: 4,
        value: v4,
        bits: 32n,
        mappedV4: v4
    };
}

function ipMatchesCidrOrExact(sourceIpStr, ruleStr) {
    if (!sourceIpStr || !ruleStr) return false;
    const rule = String(ruleStr).trim();
    if (!rule) return false;

    const src = parseIpAddress(sourceIpStr);
    if (!src) return sourceIpStr.trim() === rule;

    const slashIdx = rule.indexOf("/");
    const ipPart = slashIdx === -1 ? rule : rule.slice(0, slashIdx);
    const prefixPart = slashIdx === -1 ? null : rule.slice(slashIdx + 1);

    const target = parseIpAddress(ipPart);
    if (!target) return false;

    let srcVal = src.value;
    let targetVal = target.value;
    let totalBits = target.bits;

    if (src.version !== target.version) {
        if (target.version === 4 && src.mappedV4 !== null) {
            srcVal = src.mappedV4;
            totalBits = 32n;
        } else if (src.version === 4 && target.mappedV4 !== null && (prefixPart === null || Number(prefixPart) >= 96)) {
            srcVal = src.value;
            targetVal = target.mappedV4;
            totalBits = 32n;
        } else {
            return false;
        }
    }

    let prefixLen = totalBits;
    if (prefixPart !== null) {
        if (!/^\d{1,3}$/.test(prefixPart)) return false;
        const pNum = BigInt(parseInt(prefixPart, 10));
        if (target.version === 6 && totalBits === 32n) {
            prefixLen = pNum - 96n;
        } else {
            prefixLen = pNum;
        }
        if (prefixLen < 0n || prefixLen > totalBits) return false;
    }

    if (prefixLen === 0n) return true;
    const shift = totalBits - prefixLen;
    return (srcVal >> shift) === (targetVal >> shift);
}

function isIpMatchingList(sourceIp, ipList) {
    if (!Array.isArray(ipList) || ipList.length === 0) return false;
    return ipList.some(rule => ipMatchesCidrOrExact(sourceIp, rule));
}

function parseAsnNumber(asnVal) {
    if (typeof asnVal === "number" && Number.isFinite(asnVal)) return asnVal;
    const cleaned = String(asnVal ?? "").trim().toUpperCase().replace(/^AS/, "");
    if (!/^\d+$/.test(cleaned)) return NaN;
    return parseInt(cleaned, 10);
}

function extractObjectBasename(normalizedPath) {
    const clean = String(normalizedPath || "").split("?")[0];
    if (clean.endsWith("/")) return "";
    const parts = clean.split("/").filter(Boolean);
    if (parts.length <= 1) return "";
    return parts[parts.length - 1].toLowerCase();
}

function checkSecurityPolicy(env, request, url, targetPath, license, s3Operation, sourceIP, country, asn, userAgent) {
    const sec = license.security_policy || license.securityPolicy || {};
    const envDisableStr = String(env.DISABLE_DLP_KV_WRITES || "").trim().toLowerCase();
    const auditMode = envDisableStr === "true" || envDisableStr === "1" || env.DISABLE_DLP_KV_WRITES === true || license.disable_dlp_kv_writes === true || String(license.disable_dlp_kv_writes).trim().toLowerCase() === "true";

    const blockedUA = sec.blocked_user_agents || sec.blockedUserAgents || [];
    if (userAgent && blockedUA.some(ua => userAgent.toLowerCase().includes(String(ua).toLowerCase()))) {
        return { allowed: false, status: 403, code: "AccessDenied", message: "Access blocked by S3GW Security Policy (User-Agent in denylist).", blockReason: "USER_AGENT_DENYLIST", riskLevel: "high" };
    }

    if (!auditMode) {
        const allowedUA = sec.allowed_user_agents || sec.allowedUserAgents || [];
        if (allowedUA.length > 0 && (!userAgent || !allowedUA.some(ua => userAgent.toLowerCase().includes(String(ua).toLowerCase())))) {
            return { allowed: false, status: 403, code: "AccessDenied", message: "Access blocked by S3GW Security Policy (User-Agent not in allowlist).", blockReason: "USER_AGENT_NOT_ALLOWED", riskLevel: "high" };
        }
    }

    const blockedIps = sec.blocked_ips || sec.blockedIps || [];
    if (sourceIP && isIpMatchingList(sourceIP, blockedIps)) {
        return { allowed: false, status: 403, code: "AccessDenied", message: "Access blocked by S3GW Security Policy (IP in denylist).", blockReason: "IP_DENYLIST", riskLevel: "high" };
    }

    if (!auditMode) {
        const allowedIps = sec.allowed_ips || sec.allowedIps || [];
        if (allowedIps.length > 0 && (!sourceIP || !isIpMatchingList(sourceIP, allowedIps))) {
            return { allowed: false, status: 403, code: "AccessDenied", message: "Access blocked by S3GW Security Policy (IP not in allowlist).", blockReason: "IP_NOT_ALLOWED", riskLevel: "high" };
        }
    }

    const normCountry = String(country || "Unknown").trim().toUpperCase();
    const blockedCountries = (sec.blocked_countries || sec.blockedCountries || []).map(c => String(c).trim().toUpperCase());
    if (normCountry !== "UNKNOWN" && blockedCountries.includes(normCountry)) {
        return { allowed: false, status: 403, code: "AccessDenied", message: `Access blocked by S3GW Security Policy (Country ${country} is restricted).`, blockReason: "GEO_RESTRICTED", riskLevel: "high" };
    }

    if (!auditMode) {
        const allowedCountries = (sec.allowed_countries || sec.allowedCountries || []).map(c => String(c).trim().toUpperCase());
        if (allowedCountries.length > 0 && (normCountry === "UNKNOWN" || normCountry === "XX" || !allowedCountries.includes(normCountry))) {
            return { allowed: false, status: 403, code: "AccessDenied", message: `Access blocked by S3GW Security Policy (Country ${country} is not allowed).`, blockReason: "GEO_NOT_ALLOWED", riskLevel: "high" };
        }
    }

    const blockedAsns = (sec.blocked_asns || sec.blockedAsns || []).map(parseAsnNumber).filter(n => !isNaN(n));
    const numAsn = parseAsnNumber(asn);
    if (!isNaN(numAsn) && blockedAsns.includes(numAsn)) {
        return { allowed: false, status: 403, code: "AccessDenied", message: `Access blocked by S3GW Security Policy (ASN ${asn} is restricted).`, blockReason: "ASN_BLOCKED", riskLevel: "high" };
    }

    if (!auditMode) {
        const allowedAsns = (sec.allowed_asns || sec.allowedAsns || []).map(parseAsnNumber).filter(n => !isNaN(n));
        if (allowedAsns.length > 0 && (isNaN(numAsn) || !allowedAsns.includes(numAsn))) {
            return { allowed: false, status: 403, code: "AccessDenied", message: `Access blocked by S3GW Security Policy (ASN ${asn} is not allowed).`, blockReason: "ASN_NOT_ALLOWED", riskLevel: "high" };
        }
    }

    const ADMIN_OPERATIONS = new Set([
        "deleteBucket", "putBucketVersioning", "putBucketLifecycle", "deleteBucketLifecycle",
        "putObjectLockConfiguration", "putBucketReplication", "deleteBucketReplication",
        "putBucketPolicy", "deleteBucketPolicy", "putBucketAcl", "putBucketCors",
        "deleteBucketCors", "putBucketWebsite", "deleteBucketWebsite", "putBucketEncryption",
        "deleteBucketEncryption", "putBucketLogging", "putBucketNotification",
        "putPublicAccessBlock", "deletePublicAccessBlock", "putOwnershipControls",
        "deleteOwnershipControls", "putBucketTagging", "deleteBucketTagging"
    ]);

    const allowAdmin = sec.allow_admin_operations !== undefined ? sec.allow_admin_operations :
        (license.allow_admin_operations !== undefined ? license.allow_admin_operations : true);

    if (allowAdmin === false && ADMIN_OPERATIONS.has(s3Operation)) {
        return { allowed: false, status: 403, code: "AccessDenied", message: `Administrative operation '${s3Operation}' is forbidden by S3GW security policy on this access key.`, blockReason: "ADMIN_OPERATION_FORBIDDEN_BY_GATEWAY_POLICY", riskLevel: "high" };
    }

    const RANSOMWARE_EXTENSIONS = [
        ".locked", ".encrypted", ".ransom", ".crypt", ".lock", ".wannacry",
        ".lockbit", ".crptr", ".crypto", ".enc", ".rnsm", ".cerber", ".locky",
        ".cryptowall", ".zepto", ".odin", ".thor", ".ryuk", ".phobos", ".dharma",
        ".globeimposter", ".makop", ".medusa", ".qilin", ".akira", ".blackcat",
        ".clop", ".conti", ".darkside", ".doppelpaymer", ".maze", ".netwalker",
        ".petya", ".revil", ".sodinokibi", ".snatch", ".stop", ".djvu", ".harma",
        ".arena", ".cesar", ".crab", ".krab", ".gandcrab", ".vault", ".xtbl",
        ".yta", ".abc", ".ccc", ".vvv", ".micro", ".magic", ".exx", ".ezz", ".ecc"
    ];

    const COMPOUND_RANSOMWARE_EXTS = new Set([
        ".locked", ".encrypted", ".ransom", ".wannacry", ".lockbit", ".crptr", ".rnsm",
        ".cerber", ".locky", ".cryptowall", ".zepto", ".ryuk", ".phobos", ".dharma",
        ".globeimposter", ".makop", ".medusa", ".qilin", ".akira", ".blackcat", ".clop",
        ".conti", ".darkside", ".doppelpaymer", ".maze", ".netwalker", ".petya", ".revil",
        ".sodinokibi", ".djvu", ".gandcrab", ".xtbl"
    ]);

    const formatExt = (ext) => {
        const clean = String(ext || "").trim().toLowerCase();
        return clean.startsWith(".") ? clean : "." + clean;
    };

    const customBlockedExts = (sec.blocked_extensions || sec.blockedExtensions || []).map(formatExt);
    const killswitchActive = sec.ransomware_killswitch !== false;
    const effectiveBlockedExts = killswitchActive
        ? [...RANSOMWARE_EXTENSIONS, ...customBlockedExts]
        : customBlockedExts;

    const isPutMutation = [
        "putObject",
        "copyObject",
        "postObject",
        "uploadPart",
        "createMultipartUpload",
        "completeMultipartUpload"
    ].includes(s3Operation);

    if (isPutMutation) {
        const basename = extractObjectBasename(targetPath);
        if (basename) {
            for (const ext of effectiveBlockedExts) {
                const matchedEnd = basename.endsWith(ext);
                const matchedCompound = (COMPOUND_RANSOMWARE_EXTS.has(ext) || customBlockedExts.includes(ext)) && basename.includes(ext + ".");
                if (matchedEnd || matchedCompound) {
                    return {
                        allowed: false,
                        status: 403,
                        code: "AccessDenied",
                        message: `Ransomware protection triggered: Uploading file with extension '${ext}' is blocked by S3GW killswitch.`,
                        blockReason: "RANSOMWARE_EXTENSION_DETECTED",
                        riskLevel: "critical"
                    };
                }
            }

            if (!auditMode) {
                const allowedExts = (sec.allowed_extensions || sec.allowedExtensions || []).map(formatExt);
                if (allowedExts.length > 0) {
                    const isAllowed = allowedExts.some(ext => basename.endsWith(ext));
                    if (!isAllowed) {
                        return {
                            allowed: false,
                            status: 403,
                            code: "AccessDenied",
                            message: "Access blocked by S3GW Security Policy (File extension not in allowlist).",
                            blockReason: "EXTENSION_NOT_ALLOWED",
                            riskLevel: "high"
                        };
                    }
                }
            }
        } else if (!auditMode) {
            const allowedExts = sec.allowed_extensions || sec.allowedExtensions || [];
            if (allowedExts.length > 0 && !String(targetPath).endsWith("/")) {
                return {
                    allowed: false,
                    status: 403,
                    code: "AccessDenied",
                    message: "Access blocked by S3GW Security Policy (File extension not in allowlist).",
                    blockReason: "EXTENSION_NOT_ALLOWED",
                    riskLevel: "high"
                };
            }
        }
    }

    return { allowed: true };
}

async function incrementDlpCounter(env, counterKey, delta, ttlSeconds) {
    const kv = getLicensesKv(env);
    const now = Date.now();
    let memEntry = dlpMemoryCounters.get(counterKey);
    if (!memEntry || now > memEntry.expiresAt) {
        memEntry = { total: 0, initializedFromKv: false, expiresAt: now + ttlSeconds * 1000 };
    }

    if (!memEntry.initializedFromKv && kv) {
        const currentStr = await kv.get(counterKey);
        const kvVal = parseInt(currentStr || "0", 10);
        memEntry.total = Math.max(memEntry.total, isNaN(kvVal) ? 0 : kvVal);
        memEntry.initializedFromKv = true;
    }

    memEntry.total += delta;
    setBoundedMap(dlpMemoryCounters, MAX_DLP_COUNTER_ENTRIES, counterKey, memEntry);

    if (kv) {
        await kv.put(counterKey, memEntry.total.toString(), { expirationTtl: ttlSeconds });
    }
    return memEntry.total;
}

async function triggerKeyQuarantine(env, licenseKey, sourceIP, quarantinePayload, quarantineDuration) {
    setQuarantineCacheImmediate(licenseKey, quarantinePayload, quarantineDuration);
    const kv = getLicensesKv(env);
    if (!kv) return;
    const body = JSON.stringify(quarantinePayload);
    const puts = [
        kv.put(`quarantine:${licenseKey}`, body, { expirationTtl: quarantineDuration })
    ];
    if (sourceIP) {
        puts.push(kv.put(`quarantine:${licenseKey}:${sourceIP}`, body, { expirationTtl: quarantineDuration }));
    }
    await Promise.all(puts);
}

async function trackDlpQuotasAndQuarantine(env, licenseKey, sourceIP, license, method, s3Operation, actualBytes, deleteObjectsCount = 1) {
    try {
        const sec = license.security_policy || license.securityPolicy || {};
        const quotas = sec.dlp_quotas || sec.dlpQuotas;
        if (!quotas) return;

        const now = new Date();
        const ymd = now.toISOString().split("T")[0];
        const hour = now.getUTCHours();
        const minute = now.getUTCMinutes();

        const quarantineDuration = quotas.quarantine_duration_seconds || 3600;

        if ((method === "GET" || s3Operation === "getObject") && actualBytes > 0 && quotas.max_download_bytes_per_hour) {
            const hourKey = `dlp:${licenseKey}:bytes:${ymd}-${hour}`;
            const newTotal = await incrementDlpCounter(env, hourKey, actualBytes, 7200);

            if (newTotal > quotas.max_download_bytes_per_hour) {
                await triggerKeyQuarantine(env, licenseKey, sourceIP, {
                    reason: "QUOTA_EXFILTRATION_BYTES_EXCEEDED",
                    bytes_downloaded: newTotal,
                    limit: quotas.max_download_bytes_per_hour,
                    trigger_ip: sourceIP || "unknown",
                    quarantined_at: now.toISOString()
                }, quarantineDuration);
            }
        }

        if ((method === "GET" || s3Operation === "getObject" || s3Operation === "listObjects") && quotas.max_get_requests_per_minute) {
            const minKey = `dlp:${licenseKey}:get:${ymd}-${hour}-${minute}`;
            const newReqs = await incrementDlpCounter(env, minKey, 1, 300);

            if (newReqs > quotas.max_get_requests_per_minute) {
                await triggerKeyQuarantine(env, licenseKey, sourceIP, {
                    reason: "QUOTA_GET_REQUESTS_PER_MINUTE_EXCEEDED",
                    requests_count: newReqs,
                    limit: quotas.max_get_requests_per_minute,
                    trigger_ip: sourceIP || "unknown",
                    quarantined_at: now.toISOString()
                }, quarantineDuration);
            }
        }

        if ((method === "DELETE" || s3Operation.includes("delete")) && quotas.max_delete_requests_per_minute) {
            const minKey = `dlp:${licenseKey}:del:${ymd}-${hour}-${minute}`;
            const incrementBy = Math.max(1, Number(deleteObjectsCount) || 1);
            const newReqs = await incrementDlpCounter(env, minKey, incrementBy, 300);

            if (newReqs > quotas.max_delete_requests_per_minute) {
                await triggerKeyQuarantine(env, licenseKey, sourceIP, {
                    reason: "QUOTA_DELETE_REQUESTS_PER_MINUTE_EXCEEDED",
                    requests_count: newReqs,
                    limit: quotas.max_delete_requests_per_minute,
                    trigger_ip: sourceIP || "unknown",
                    quarantined_at: now.toISOString()
                }, quarantineDuration);
            }
        }
    } catch (e) {
        console.error("trackDlpQuotasAndQuarantine error:", e.message);
    }
}

function buildLogEntry({ licenseKey, gwHost, sourceIP, country, city, asn, asOrganization, userAgent, gwAccessKey,
    method, s3Operation, path, bucket, contentLength, status, durationMs, authMeta, securityDecision }) {
    const flags = [];
    if (["deleteObject", "deleteObjects", "deleteBucket"].includes(s3Operation)) flags.push("delete_operation");
    if (["putObject", "copyObject", "uploadPart", "postObject", "createMultipartUpload", "completeMultipartUpload"].includes(s3Operation)) flags.push("write_operation");
    if (s3Operation === "getObject" || s3Operation === "headObject") flags.push("read_operation");
    if (s3Operation === "createPresignedUrl") flags.push("presign_token_minted");

    if (authMeta?.mode && authMeta.mode !== "sigv4_header") {
        flags.push("presigned_access");
        flags.push(authMeta.mode);
    }
    if (authMeta?.singleUse) flags.push("single_use_token");
    if (authMeta?.ipBound) flags.push("ip_bound_token");

    const ADMIN_KEYWORDS = ["Versioning", "Lifecycle", "Policy", "Cors", "Website", "Replication", "ObjectLock", "Encryption", "Logging", "Notification", "PublicAccess", "Ownership", "Acl"];
    if (ADMIN_KEYWORDS.some(kw => s3Operation.includes(kw)) || s3Operation.includes("BucketTagging")) {
        flags.push("admin_operation");
    }
    if (s3Operation.includes("Tagging")) flags.push("tagging_change");

    if (status >= 400) flags.push("error_response");
    if (status === 403) flags.push("access_denied");
    if (status === 429) flags.push("dlp_quarantine_blocked");

    let action = "allowed";
    let blockReason = null;
    let riskLevel = "info";

    if (flags.includes("delete_operation")) riskLevel = "high";
    else if (flags.includes("admin_operation")) {
        riskLevel = (method === "GET" || method === "HEAD") ? "low" : "high";
    }
    else if (flags.includes("write_operation")) riskLevel = "medium";

    if (status >= 400 && riskLevel === "info") riskLevel = "low";

    if (securityDecision && !securityDecision.allowed) {
        action = "blocked";
        blockReason = securityDecision.blockReason || "SECURITY_POLICY_VIOLATION";
        riskLevel = securityDecision.riskLevel || "high";
        flags.push("security_policy_blocked");
        if (blockReason) flags.push(blockReason.toLowerCase());
    }

    const keyPath = path === `/${bucket}` ? "/" : path.replace(/^\/[^/]+\//, "/");

    const entry = {
        ts: new Date().toISOString(),
        licence: licenseKey,
        gateway: {
            host: gwHost || "gateway.s3gw.com",
            ip: sourceIP,
            country,
            city,
            asn,
            as_organization: asOrganization,
            user_agent: userAgent,
            access_key_used: gwAccessKey,
            auth_mode: authMeta?.mode || "sigv4_header",
        },
        operation: {
            method,
            type: s3Operation,
            bucket,
            key: keyPath,
        },
        response: {
            status,
            bytes: contentLength || 0,
            duration_ms: durationMs,
        },
        security: {
            action,
            risk_level: riskLevel,
            block_reason: blockReason,
            flags,
        },
    };

    if (authMeta?.tokenJti || authMeta?.correlationId || authMeta?.singleUse !== undefined || authMeta?.ipBound) {
        entry.correlation = {
            token_jti: authMeta.tokenJti || null,
            correlation_id: authMeta.correlationId || null,
            single_use: Boolean(authMeta.singleUse),
            ip_bound: authMeta.ipBound || null,
        };
    }

    return entry;
}

function generateRandomHex(byteLen = 3) {
    const arr = new Uint8Array(byteLen);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function writeLog(env, licenseKey, logEntry) {
    try {
        const r2 = getR2Gateway(env);
        if (!r2) return;
        const now = new Date();
        const year = now.getUTCFullYear();
        const month = String(now.getUTCMonth() + 1).padStart(2, "0");
        const day = String(now.getUTCDate()).padStart(2, "0");
        const ts = now.getTime();
        const safePrefix = String(licenseKey || "_unauthenticated").replace(/[\/\\]/g, "_");
        const shortKey = safePrefix.substring(0, 8);
        const randSuffix = generateRandomHex(3);

        const r2Path = `${safePrefix}/${year}/${month}/${day}/log${shortKey}${ts}_${randSuffix}.json`;

        await r2.put(r2Path, JSON.stringify(logEntry), {
            httpMetadata: { contentType: "application/json" },
        });
    } catch (e) {
        console.error("writeLog error:", e.message);
    }
}

function extractAccessKeyFromAuth(authHeader) {
    const match = authHeader.match(/Credential=([^/,]+)/);
    return match ? match[1] : "-";
}

function uriEncode(str) {
    return encodeURIComponent(str).replace(/[!'()*]/g, function (c) {
        return "%" + c.charCodeAt(0).toString(16).toUpperCase();
    });
}

function escapeXml(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function parseAllowedOrigins(rawOrigins) {
    if (!rawOrigins) return [];
    if (Array.isArray(rawOrigins)) return rawOrigins.map(o => String(o).trim()).filter(Boolean);
    return String(rawOrigins).split(",").map(o => o.trim()).filter(Boolean);
}

function applyCorsHeaders(headers, request, allowedOrigins = []) {
    const reqOrigin = request?.headers?.get("Origin");
    if (!reqOrigin) return;

    if (allowedOrigins.length > 0) {
        if (allowedOrigins.includes("*") || allowedOrigins.includes(reqOrigin)) {
            headers.set("Access-Control-Allow-Origin", allowedOrigins.includes("*") ? "*" : reqOrigin);
            headers.set("Access-Control-Allow-Methods", "GET, PUT, DELETE, HEAD, POST, OPTIONS");
            headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-MD5, Range, X-Amz-Date, X-Amz-Content-Sha256, X-Amz-Security-Token, X-Amz-Copy-Source, X-Amz-Acl, X-Amz-User-Agent");
            headers.set("Vary", "Origin");
        }
    }
}

function handleOptionsPreflight(request, allowedOrigins = []) {
    const headers = new Headers({
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store"
    });
    const reqOrigin = request.headers.get("Origin");
    if (reqOrigin && allowedOrigins.length > 0 && (allowedOrigins.includes("*") || allowedOrigins.includes(reqOrigin))) {
        headers.set("Access-Control-Allow-Origin", allowedOrigins.includes("*") ? "*" : reqOrigin);
        headers.set("Access-Control-Allow-Methods", "GET, PUT, DELETE, HEAD, POST, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-MD5, Range, X-Amz-Date, X-Amz-Content-Sha256, X-Amz-Security-Token, X-Amz-Copy-Source, X-Amz-Acl, X-Amz-User-Agent");
        headers.set("Access-Control-Max-Age", "86400");
        headers.set("Vary", "Origin");
    }
    return new Response(null, { status: 204, headers });
}

function buildSyntheticListBucketsResponse(license, request, allowedOrigins = []) {
    const createdDate = license.gateway?.created_at || "2026-01-01T00:00:00.000Z";
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>s3gw</ID>
    <DisplayName>s3gw</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>${escapeXml(license.bucket)}</Name>
      <CreationDate>${escapeXml(createdDate)}</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>`;
    const headers = new Headers({
        "Content-Type": "application/xml; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store"
    });
    applyCorsHeaders(headers, request, allowedOrigins);
    return new Response(xml, { status: 200, headers });
}

function errorResponse(status, code, message, gwHost = "gateway.s3gw.com", request = null, allowedOrigins = []) {
    const reqId = "s3gw-" + generateRandomHex(6);
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>${escapeXml(code)}</Code>
  <Message>${escapeXml(message)}</Message>
  <RequestId>${escapeXml(reqId)}</RequestId>
  <HostId>${escapeXml(gwHost)}</HostId>
</Error>`;
    const headers = new Headers({
        "Content-Type": "application/xml; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-transform, no-store",
    });
    applyCorsHeaders(headers, request, allowedOrigins);
    return new Response(xml, { status, headers });
}

function createAwsChunkedDecoderStream() {
    let buffer = new Uint8Array(0);
    let state = "HEADER";
    let bytesRemaining = 0;

    return new TransformStream({
        transform(chunk, controller) {
            if (state === "DONE") return;

            const newBuf = new Uint8Array(buffer.length + chunk.length);
            newBuf.set(buffer, 0);
            newBuf.set(chunk, buffer.length);
            buffer = newBuf;

            let offset = 0;
            while (offset < buffer.length) {
                if (state === "HEADER") {
                    let crlfIdx = -1;
                    for (let i = offset; i < buffer.length - 1; i++) {
                        if (buffer[i] === 13 && buffer[i + 1] === 10) {
                            crlfIdx = i;
                            break;
                        }
                    }
                    if (crlfIdx === -1) break;

                    const headerStr = new TextDecoder().decode(buffer.subarray(offset, crlfIdx));
                    const hexSizeStr = headerStr.split(";")[0].trim();
                    bytesRemaining = parseInt(hexSizeStr, 16);
                    offset = crlfIdx + 2;

                    if (isNaN(bytesRemaining)) {
                        controller.error(new Error("Invalid aws-chunked header: " + headerStr));
                        return;
                    }

                    if (bytesRemaining === 0) {
                        state = "DONE";
                        break;
                    } else {
                        state = "DATA";
                    }
                } else if (state === "DATA") {
                    const avail = buffer.length - offset;
                    const toRead = Math.min(avail, bytesRemaining);
                    if (toRead > 0) {
                        controller.enqueue(buffer.subarray(offset, offset + toRead));
                        offset += toRead;
                        bytesRemaining -= toRead;
                    }
                    if (bytesRemaining === 0) {
                        state = "TRAILING_CRLF";
                    } else {
                        break;
                    }
                } else if (state === "TRAILING_CRLF") {
                    if (buffer.length - offset < 2) break;
                    if (buffer[offset] === 13 && buffer[offset + 1] === 10) {
                        offset += 2;
                        state = "HEADER";
                    } else {
                        controller.error(new Error("Expected CRLF after chunk data"));
                        return;
                    }
                }
            }
            if (offset > 0) {
                buffer = buffer.slice(offset);
            }
        }
    });
}

