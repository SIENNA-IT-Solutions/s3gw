/**
 * Cloudflare Worker — S3 Gateway Standalone (Audit & Logging)
 *
 * Environment Variables (Bindings) to configure:
 * 1. LICENSES_KV (KV Namespace)
 * 2. R2_GATEWAY (R2 Bucket)
 * 3. GATEWAY_HOST (Global Variable, e.g., gateway.domain.tld)
 * 4. DISABLE_DLP_KV_WRITES (Global Variable, optional boolean)
 * 5. CORS_ALLOWED_ORIGINS (Global Variable, optional comma-separated origins)
 *
 * Note: Bind this Worker to your prefered's subdomain (e.g., gateway.domain.tld).
 */

const LOGGABLE_METHODS = new Set(["PUT", "DELETE", "POST", "GET"]);

const LOGGABLE_POST_ACTIONS = new Set([
    "completeMultipartUpload",
    "createMultipartUpload",
    "restoreObject",
    "deleteObjects",
]);

// Cache mémoire global borné (LRU) pour réduire les appels KV (coût & latence)
const kvCache = new Map();
const CACHE_TTL_MS = 60000; // 60 secondes pour licences et quarantaines actives
const NEGATIVE_CACHE_TTL_MS = 5000; // 5 secondes pour les entrées absentes (null)
const MAX_KV_CACHE_ENTRIES = 1000;

// Cache mémoire borné (LRU) pour les clés de signature SigV4 journalières (CryptoKey)
const signingKeyCache = new Map();
const SIGNING_KEY_TTL_MS = 24 * 60 * 60 * 1000; // 24 heures
const MAX_SIGNING_KEY_CACHE_ENTRIES = 500;

// Accumulateur mémoire DLP pour éviter la fenêtre aveugle et les race conditions sur un même isolate
const dlpMemoryCounters = new Map();
const MAX_DLP_COUNTER_ENTRIES = 2000;

// Fenêtre anti-rejeu SigV4 (standard AWS S3 : ±15 minutes)
const MAX_SIGV4_CLOCK_SKEW_MS = 15 * 60 * 1000;

// Validation stricte du format d'Access Key avant tout appel KV (anti-DoS cache/KV)
const ACCESS_KEY_FORMAT_REGEX = /^[A-Za-z0-9_.-]{8,128}$/;

function setBoundedMap(map, maxEntries, key, value) {
    if (map.has(key)) {
        map.delete(key);
    } else if (map.size >= maxEntries) {
        const oldestKey = map.keys().next().value;
        if (oldestKey !== undefined) map.delete(oldestKey);
    }
    map.set(key, value);
}

async function getCachedKV(env, key, customNegativeTtlMs = NEGATIVE_CACHE_TTL_MS) {
    const now = Date.now();
    if (kvCache.has(key)) {
        const cached = kvCache.get(key);
        const ttl = cached.ttl ?? (cached.data === null ? customNegativeTtlMs : CACHE_TTL_MS);
        if (now - cached.timestamp < ttl) {
            // Promotion LRU
            kvCache.delete(key);
            kvCache.set(key, cached);
            return cached.data;
        }
        kvCache.delete(key);
    }
    const data = await env.LICENSES_KV.get(key, { type: "json" });
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

// Décodage URI récursif (protège contre %6C, %256C, etc.)
function fullyDecodeURIComponent(str, maxPasses = 5) {
    let current = String(str ?? "");
    for (let i = 0; i < maxPasses; i++) {
        try {
            const decoded = decodeURIComponent(current);
            if (decoded === current) break;
            current = decoded;
        } catch (e) {
            // Décodage caractère par caractère si une séquence %XX isolée est malformée
            const partial = current.replace(/%[0-9a-fA-F]{2}/g, (m) => {
                try { return decodeURIComponent(m); } catch (_) { return m; }
            });
            if (partial === current) break;
            current = partial;
        }
    }
    return current;
}

// Normalisation sécurisée du chemin S3 (décodage récursif + détection de traversal)
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

        // Résolution préliminaire du chemin pour journalisation SIEM homogène
        let rawTargetPath = url.pathname;
        const hostName = url.hostname.toLowerCase();
        if (hostName !== configuredGatewayHost && hostName.endsWith("." + configuredGatewayHost)) {
            const vhBucket = hostName.slice(0, -(configuredGatewayHost.length + 1));
            rawTargetPath = `/${vhBucket}${rawTargetPath === "/" ? "" : rawTargetPath}`;
        }

        const { normalizedPath, segments: pathParts, hasTraversal } = normalizeAndInspectPath(rawTargetPath);
        const requestedBucket = pathParts.length > 0 ? pathParts[0] : "";
        const s3Operation = resolveS3Operation(method, normalizedPath, queryString, request.headers);

        const logAndReject = (logLicenseKey, gwKeyUsed, bucketForLog, status, code, message, blockReason, riskLevel = "high", policyCorsOrigins = corsAllowedOrigins) => {
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

        if (!authHeader.startsWith("AWS4-HMAC-SHA256")) {
            return logAndReject(
                "_unauthenticated",
                "NONE",
                requestedBucket,
                403,
                "AccessDenied",
                "AWS Signature V4 requise.",
                "MISSING_AWS_SIGV4_AUTH",
                "medium"
            );
        }

        const gwAccessKeyReceived = extractAccessKeyFromAuth(authHeader);

        if (!gwAccessKeyReceived || gwAccessKeyReceived === "-" || !ACCESS_KEY_FORMAT_REGEX.test(gwAccessKeyReceived)) {
            return logAndReject(
                "_unauthenticated",
                gwAccessKeyReceived || "INVALID",
                requestedBucket,
                403,
                "InvalidAccessKeyId",
                "Access key invalide.",
                "MALFORMED_ACCESS_KEY_ID",
                "high"
            );
        }

        const licenseKey = gwAccessKeyReceived;

        // Optimisation majeure : Cache mémoire LRU + Get parallèle (quarantaine globale par clé ET par IP)
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
                "high"
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
                licenseCorsOrigins
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
                licenseCorsOrigins
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
                licenseCorsOrigins
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
                licenseCorsOrigins
            );
        }

        const licenseGatewaySecretKey = license.gateway.secret_key || license.gateway.secretKey;
        const sigResult = await verifyAwsSigV4(request, licenseGatewaySecretKey, url);
        if (!sigResult.valid) {
            const isSkew = sigResult.reason === "RequestTimeTooSkewed";
            return logAndReject(
                licenseKey,
                gwAccessKeyReceived,
                license.bucket,
                403,
                isSkew ? "RequestTimeTooSkewed" : "SignatureDoesNotMatch",
                isSkew ? "L'horodatage de la requête dépasse la fenêtre autorisée (15 minutes)." : "Signature AWS invalide.",
                isSkew ? "SIGV4_REPLAY_OR_CLOCK_SKEW" : "INVALID_AWS_SIGNATURE",
                "high",
                licenseCorsOrigins
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
                licenseCorsOrigins
            );
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
                licenseCorsOrigins
            );
        }

        // Inspection stricte du header x-amz-copy-source (anti-exfiltration cross-bucket)
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
                    licenseCorsOrigins
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
                licenseCorsOrigins
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
                licenseCorsOrigins
            );
        }

        // Réponse synthétique ListAllMyBucketsResult sur GET / pour la compatibilité des clients GUI (Cyberduck, S3 Browser, WinSCP)
        if (!requestedBucket && license.bucket) {
            if (method === "GET") {
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
                licenseCorsOrigins
            );
        }

        const envDisableStr = String(env.DISABLE_DLP_KV_WRITES || "").trim().toLowerCase();
        const disableDlpKv = envDisableStr === "true" || envDisableStr === "1" || env.DISABLE_DLP_KV_WRITES === true || license.disable_dlp_kv_writes === true || String(license.disable_dlp_kv_writes).trim().toLowerCase() === "true";

        // Comptage exact du nombre d'objets dans un batch POST ?delete (deleteObjects)
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

            // Blocage préventif immédiat si un seul batch delete dépasse déjà le quota par minute
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
                    licenseCorsOrigins
                );
            }
        }

        const shouldLog = decideShouldLog(method, s3Operation, contentLength);

        const backendResp = await forwardToBackend(request, url, rawTargetPath, license, env, preReadBodyBuffer);
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
                securityDecision: undefined
            });

            ctx.waitUntil(writeLog(env, licenseKey, logEntry));
        }

        const respHeaders = new Headers(backendResp.headers);
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
            // Fallback XOR constant-time
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

        // Validation anti-rejeu (horodatage obligatoire, cohérence dateStamp et skew <= ±15 min)
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

// Cache mémoire de la CryptoKey dérivée (évite 8 importKey + 8 sign WebCrypto par requête)
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

async function forwardToBackend(request, originalUrl, targetPath, license, env, preReadBodyBuffer = null) {
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
        const prefixRegex = new RegExp(`^/+${ bucketName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") }(?=/|$)`);
        backendPath = targetPath.replace(prefixRegex, "");
        if (!backendPath.startsWith("/")) backendPath = "/" + backendPath;
    }

    const backendBase = `${scheme}${backendEndpoint}`;
    const backendHost = backendEndpoint;

    const backendUrl = new URL(backendPath + originalUrl.search, backendBase);

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

    // Normalisation SigV4 stricte (trim + collapse des espaces multiples)
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

// --- Parsing & Matching IP (IPv4, IPv6 canonisé, IPv4-mapped IPv6 et plages CIDR) ---
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
        // Support des adresses IPv4-mapped / embedded dans IPv6 (ex: ::ffff:185.220.101.5)
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

        // Si c'est une adresse IPv4-mapped (::ffff:0:0/96), on expose aussi son équivalent IPv4
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

    // Compatibilité croisée IPv4 <-> IPv4-mapped IPv6 (::ffff:a.b.c.d)
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

// Extraction du nom de fichier objet (basename) hors nom de bucket et dossiers intermédiaires
function extractObjectBasename(normalizedPath) {
    const clean = String(normalizedPath || "").split("?")[0];
    if (clean.endsWith("/")) return ""; // Dossier S3 : pas d'extension de fichier
    const parts = clean.split("/").filter(Boolean);
    if (parts.length <= 1) return ""; // Seulement le nom du bucket
    return parts[parts.length - 1].toLowerCase();
}

function checkSecurityPolicy(env, request, url, targetPath, license, s3Operation, sourceIP, country, asn, userAgent) {
    const sec = license.security_policy || license.securityPolicy || {};
    const envDisableStr = String(env.DISABLE_DLP_KV_WRITES || "").trim().toLowerCase();
    const auditMode = envDisableStr === "true" || envDisableStr === "1" || env.DISABLE_DLP_KV_WRITES === true || license.disable_dlp_kv_writes === true || String(license.disable_dlp_kv_writes).trim().toLowerCase() === "true";

    // 0. Filtrage par User-Agent (Fail-Closed sur allowlist)
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

    // 1. Filtrage par liste noire / blanche d'IP (Support IPv4, IPv6 canonisé & CIDR + Fail-Closed)
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

    // 2. Filtrage Géographique (Pays d'origine via Cloudflare Edge, Fail-Closed sur allowlist)
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

    // 3. Filtrage ASN / ISP (Fail-Closed sur allowlist)
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

    // 4. Protection des opérations d'Administration (allow_admin_operations)
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

    // 5. Ransomware Killswitch & Extension Filtering sur écritures (évalué sur le basename décodé de l'objet)
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

    // Familles non-ambiguës pouvant apparaître en avant-dernière extension (ex: file.pdf.lockbit.id123)
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
    const killswitchActive = sec.ransomware_killswitch !== false; // Activé par défaut
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
    const now = Date.now();
    let memEntry = dlpMemoryCounters.get(counterKey);
    if (!memEntry || now > memEntry.expiresAt) {
        memEntry = { total: 0, initializedFromKv: false, expiresAt: now + ttlSeconds * 1000 };
    }

    if (!memEntry.initializedFromKv) {
        const currentStr = await env.LICENSES_KV.get(counterKey);
        const kvVal = parseInt(currentStr || "0", 10);
        memEntry.total = Math.max(memEntry.total, isNaN(kvVal) ? 0 : kvVal);
        memEntry.initializedFromKv = true;
    }

    memEntry.total += delta;
    setBoundedMap(dlpMemoryCounters, MAX_DLP_COUNTER_ENTRIES, counterKey, memEntry);

    await env.LICENSES_KV.put(counterKey, memEntry.total.toString(), { expirationTtl: ttlSeconds });
    return memEntry.total;
}

async function triggerKeyQuarantine(env, licenseKey, sourceIP, quarantinePayload, quarantineDuration) {
    // Mise en quarantaine immédiate en mémoire (0ms de fenêtre aveugle sur l'isolate)
    setQuarantineCacheImmediate(licenseKey, quarantinePayload, quarantineDuration);
    const body = JSON.stringify(quarantinePayload);
    const puts = [
        env.LICENSES_KV.put(`quarantine:${licenseKey}`, body, { expirationTtl: quarantineDuration })
    ];
    if (sourceIP) {
        puts.push(env.LICENSES_KV.put(`quarantine:${licenseKey}:${sourceIP}`, body, { expirationTtl: quarantineDuration }));
    }
    await Promise.all(puts);
}

async function trackDlpQuotasAndQuarantine(env, licenseKey, sourceIP, license, method, s3Operation, actualBytes, deleteObjectsCount = 1) {
    try {
        const sec = license.security_policy || license.securityPolicy || {};
        const quotas = sec.dlp_quotas || sec.dlpQuotas;
        if (!quotas) return;

        const now = new Date();
        const ymd = now.toISOString().split("T")[0]; // YYYY-MM-DD
        const hour = now.getUTCHours();
        const minute = now.getUTCMinutes();

        const quarantineDuration = quotas.quarantine_duration_seconds || 3600;

        // 1. Quota d'exfiltration en téléchargement (Bytes per hour, global sur la clé de licence)
        if ((method === "GET" || s3Operation === "getObject") && actualBytes > 0 && quotas.max_download_bytes_per_hour) {
            const hourKey = `dlp:${licenseKey}:bytes:${ymd}-${hour}`;
            const newTotal = await incrementDlpCounter(env, hourKey, actualBytes, 7200); // TTL 2h

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

        // 2. Quota de requêtes GET par minute (Anti-aspiration / scan, global sur la clé de licence)
        if ((method === "GET" || s3Operation === "getObject" || s3Operation === "listObjects") && quotas.max_get_requests_per_minute) {
            const minKey = `dlp:${licenseKey}:get:${ymd}-${hour}-${minute}`;
            const newReqs = await incrementDlpCounter(env, minKey, 1, 300); // TTL 5m

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

        // 3. Quota de requêtes DELETE par minute (Anti-wiper / destruction de masse : incrémente de X objets en 1 seule opération KV)
        if ((method === "DELETE" || s3Operation.includes("delete")) && quotas.max_delete_requests_per_minute) {
            const minKey = `dlp:${licenseKey}:del:${ymd}-${hour}-${minute}`;
            const incrementBy = Math.max(1, Number(deleteObjectsCount) || 1);
            const newReqs = await incrementDlpCounter(env, minKey, incrementBy, 300); // TTL 5m

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
    method, s3Operation, path, bucket, contentLength, status, durationMs, securityDecision }) {

    const flags = [];
    if (["deleteObject", "deleteObjects", "deleteBucket"].includes(s3Operation)) flags.push("delete_operation");
    if (["putObject", "copyObject", "uploadPart", "postObject", "createMultipartUpload", "completeMultipartUpload"].includes(s3Operation)) flags.push("write_operation");
    if (s3Operation === "getObject") flags.push("read_operation");

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

    return {
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
}

function generateRandomHex(byteLen = 3) {
    const arr = new Uint8Array(byteLen);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function writeLog(env, licenseKey, logEntry) {
    try {
        if (!env.R2_GATEWAY) return;
        const now = new Date();
        const year = now.getUTCFullYear();
        const month = String(now.getUTCMonth() + 1).padStart(2, "0");
        const day = String(now.getUTCDate()).padStart(2, "0");
        const ts = now.getTime();
        const safePrefix = String(licenseKey || "_unauthenticated").replace(/[^A-Za-z0-9_.-]/g, "_");
        const shortKey = safePrefix.substring(0, 8);
        const randSuffix = generateRandomHex(3);

        const r2Path = `${safePrefix}/${year}/${month}/${day}/log${shortKey}${ts}_${randSuffix}.json`;

        await env.R2_GATEWAY.put(r2Path, JSON.stringify(logEntry), {
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
