/**
 * ============================================================================
 * S3GW — Universal Cloudflare Edge S3 Firewall & IPS Proxy
 * ============================================================================
 * 
 * An open-source, provider-agnostic, zero-trust S3 reverse-proxy executing at
 * cloud scale on Cloudflare Workers. Intercepts, validates (AWS SigV4), logs,
 * and actively defends S3 buckets across any cloud provider (AWS, R2, Scaleway,
 * Hetzner, OVH, Backblaze B2, Google Cloud Storage, etc.).
 * 
 * Developed by SIENNA IT Solutions (https://sienna.dev)
 * Core Open-Source Perimeter Module for tamper (https://tamper.fr)
 * License: MIT
 * 
 * Key Capabilities:
 *  1. Transparent Proxying & Resigning: 100% S3 API & AWS Signature V4 compliant.
 *  2. Security Policy Engine (IPS/WAF): Geo-blocking, ASN/IP denylists, and
 *     Ransomware Killswitch (.locked, .encrypted, etc. payload blocking).
 *  3. DLP Exfiltration Guard: Sliding volumetric quotas (bytes/hr) and rate limiting
 *     (GET/DELETE requests/min) with automatic ephemeral KV quarantine.
 *  4. Real-Time SIEM Audit Logging: Asynchronous JSON logging (`ctx.waitUntil`)
 *     to Cloudflare R2, ready for Splunk, Datadog, Elastic Security, or Wazuh.
 * 
 * Required Cloudflare Worker Bindings:
 *  - LICENSES_KV : KV Namespace storing client configurations (`s3gwLicence.json`)
 *  - R2_GATEWAY  : R2 Bucket storing enriched JSON audit logs
 *  - GATEWAY_HOST: Environment variable (default: "s3gw.yourdomain.com")
 * ============================================================================
 *
 * Example JSON Audit Log Stored in Cloudflare R2:
 * ----------------------------------------------------------------------------
 * [Example 1: Allowed PUT Operation (File Upload)]
 * {
 *   "ts": "2026-07-11T19:45:12.304Z",
 *   "licence": "DEMO_S3GW_KEY",
 *   "gateway": {
 *     "ip": "81.252.14.99",
 *     "country": "FR",
 *     "city": "Paris",
 *     "asn": "AS3215",
 *     "as_organization": "Orange SA",
 *     "user_agent": "aws-cli/2.15.0 Python/3.11.6 Linux/5.10.0-8-amd64",
 *     "access_key_used": "DEMO_S3GW_KEY"
 *   },
 *   "operation": {
 *     "method": "PUT",
 *     "type": "putObject",
 *     "bucket": "my-target-bucket",
 *     "key": "/reports/2026_Q3_financial_audit.pdf"
 *   },
 *   "response": {
 *     "status": 200,
 *     "bytes": 4582910,
 *     "duration_ms": 142
 *   },
 *   "security": {
 *     "risk_level": "medium",
 *     "flags": ["write_operation"]
 *   }
 * }
 * 
 * [Example 2: Blocked / Quarantined Access Attempt]
 * {
 *   "ts": "2026-07-11T19:48:05.892Z",
 *   "licence": "DEMO_S3GW_KEY",
 *   "gateway": {
 *     "ip": "185.220.101.5",
 *     "country": "RU",
 *     "city": "Moscow",
 *     "asn": "AS24940",
 *     "as_organization": "Hetzner Online GmbH",
 *     "user_agent": "aws-cli/2.15.0 Python/3.11.6 Linux/x86_64",
 *     "access_key_used": "DEMO_S3GW_KEY"
 *   },
 *   "operation": {
 *     "method": "GET",
 *     "type": "getObject",
 *     "bucket": "my-target-bucket",
 *     "key": "/database/backup_prod.sql"
 *   },
 *   "response": {
 *     "status": 403,
 *     "bytes": 0,
 *     "duration_ms": 14
 *   },
 *   "security": {
 *     "action": "blocked",
 *     "risk_level": "high",
 *     "block_reason": "GEO_RESTRICTED",
 *     "flags": ["read_operation", "access_denied", "geo_restricted", "security_policy_blocked"]
 *   }
 * }
 * 
 * Example KV Client License Object (Key = Access Key ID, e.g., "DEMO_S3GW_KEY"):
 * ----------------------------------------------------------------------------
 * {
 *   "activated": true,
 *   "expires_at": "2030-12-31T23:59:59Z",
 *   "gateway": {
 *     "enabled": true,
 *     "access_key": "DEMO_S3GW_KEY",
 *     "secret_key": "4c38d72e61be92d4b68e0d9843c081e3f892a0d1762c"
 *   },
 *   "bucket": "my-target-bucket",
 *   "endpoint": "s3.eu-west-3.amazonaws.com",
 *   "region": "eu-west-3",
 *   "accessKey": "AKIAX_REAL_S3_ACCESS_KEY",
 *   "secretKey": "REAL_S3_SECRET_KEY_abc123",
 *   "forceVirtualHost": true,
 *   "forcePathStyle": false,
 *   "security_policy": {
 *     "allowed_countries": ["FR", "DE", "BE", "CH", "US"],
 *     "blocked_countries": ["RU", "CN", "KP", "IR"],
 *     "blocked_asns": [4134, 4837, 3462],
 *     "allowed_ips": [],
 *     "blocked_ips": ["185.220.101.5"],
 *     "allow_admin_operations": false,
 *     "ransomware_killswitch": true,
 *     "dlp_quotas": {
 *       "max_download_bytes_per_hour": 10737418240,
 *       "max_get_requests_per_minute": 600,
 *       "max_delete_requests_per_minute": 60,
 *       "quarantine_duration_seconds": 3600
 *     }
 *   }
 * }
 * ============================================================================
 */

const LOGGABLE_METHODS = new Set(["PUT", "DELETE", "POST", "GET"]);

const LOGGABLE_POST_ACTIONS = new Set([
    "completeMultipartUpload",
    "createMultipartUpload",
    "restoreObject",
    "deleteObjects",
]);

export default {
    async fetch(request, env, ctx) {
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, PUT, DELETE, HEAD, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                },
            });
        }

        const url = new URL(request.url);
        const authHeader = request.headers.get("Authorization") || "";
        const configuredGatewayHost = (env.GATEWAY_HOST || "s3gw.yourdomain.com").toLowerCase();

        if (!authHeader.startsWith("AWS4-HMAC-SHA256")) {
            return errorResponse(403, "AccessDenied", "AWS Signature V4 requise.", configuredGatewayHost);
        }

        const gwAccessKeyReceived = extractAccessKeyFromAuth(authHeader);

        if (!gwAccessKeyReceived || gwAccessKeyReceived === "-") {
            return errorResponse(403, "InvalidAccessKeyId", "Access key invalide.", configuredGatewayHost);
        }

        const licenseKey = gwAccessKeyReceived;
        // Optimization: Parallel KV fetch for license object and quarantine status (`0ms sequential latency`)
        const [license, quarantine] = await Promise.all([
            env.LICENSES_KV.get(licenseKey, { type: "json" }),
            env.LICENSES_KV.get(`quarantine:${licenseKey}`, { type: "json" })
        ]);

        if (!license) {
            return errorResponse(403, "InvalidAccessKeyId", "Clé de licence inconnue.", configuredGatewayHost);
        }

        if (!license.activated) {
            return errorResponse(403, "AccessDenied", "Licence désactivée.", configuredGatewayHost);
        }

        if (new Date(license.expires_at) < new Date()) {
            return errorResponse(403, "AccessDenied", "Licence expirée.", configuredGatewayHost);
        }

        if (!license.gateway?.enabled) {
            return errorResponse(403, "AccessDenied", "Gateway non activée pour cette licence.", configuredGatewayHost);
        }

        const licenseGatewayAccessKey = license.gateway.access_key || license.gateway.accessKey;
        if (licenseGatewayAccessKey !== gwAccessKeyReceived) {
            return errorResponse(403, "InvalidAccessKeyId", "Access key ne correspond pas à cette licence.", configuredGatewayHost);
        }

        const licenseGatewaySecretKey = license.gateway.secret_key || license.gateway.secretKey;
        const sigValid = await verifyAwsSigV4(request, licenseGatewaySecretKey, url);
        if (!sigValid) {
            return errorResponse(403, "SignatureDoesNotMatch", "Signature AWS invalide.", configuredGatewayHost);
        }

        let targetPath = url.pathname;
        const hostName = url.hostname.toLowerCase();
        if (hostName !== configuredGatewayHost && hostName.endsWith("." + configuredGatewayHost)) {
            const vhBucket = hostName.slice(0, -(configuredGatewayHost.length + 1));
            targetPath = `/${vhBucket}${targetPath === '/' ? '' : targetPath}`;
        }

        const method = request.method;
        const path = targetPath;
        const queryString = url.search;
        const contentLength = parseInt(request.headers.get("Content-Length") || "0", 10);
        const userAgent = request.headers.get("User-Agent") || "";
        const sourceIP = request.headers.get("CF-Connecting-IP") || "";
        const country = request.cf?.country || "Unknown";
        const city = request.cf?.city || "Unknown";
        const asn = request.cf?.asn || "N/A";
        const asOrganization = request.cf?.asOrganization || "Unknown ISP";
        const s3Operation = resolveS3Operation(method, path, queryString);

        const startMs = Date.now();

        // 1. DLP Exfiltration Guard Check: Immediate blocking if access key is currently quarantined
        if (quarantine) {
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
                s3Operation,
                path,
                bucket: license.bucket,
                contentLength: contentLength,
                status: 429,
                durationMs,
                securityDecision: {
                    allowed: false,
                    status: 429,
                    code: "SlowDown",
                    message: `S3GW Exfiltration Guard: Access key is quarantined (${quarantine.reason || "Quota exceeded"}).`,
                    blockReason: "QUARANTINED_BY_QUOTA",
                    riskLevel: "high"
                }
            });
            ctx.waitUntil(writeLog(env, licenseKey, logEntry));
            return errorResponse(429, "SlowDown", `S3GW Exfiltration Guard: Access key is quarantined (${quarantine.reason || "Quota exceeded"}). Try again later.`, configuredGatewayHost);
        }

        // 2. Security Policy Engine (IPS/WAF Inline Check: Geo, ASN, IP, Ransomware Killswitch)
        const secDecision = checkSecurityPolicy(request, url, targetPath, license, s3Operation, sourceIP, country, asn);
        if (!secDecision.allowed) {
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
                s3Operation,
                path,
                bucket: license.bucket,
                contentLength: contentLength,
                status: secDecision.status || 403,
                durationMs,
                securityDecision: secDecision,
            });

            ctx.waitUntil(writeLog(env, licenseKey, logEntry));
            return errorResponse(secDecision.status || 403, secDecision.code || "AccessDenied", secDecision.message, configuredGatewayHost);
        }

        const shouldLog = decideShouldLog(method, s3Operation, contentLength);

        const backendResp = await forwardToBackend(request, url, targetPath, license, env);
        const durationMs = Date.now() - startMs;

        const respBytes = parseInt(backendResp.headers.get("Content-Length") || "0", 10);
        const actualBytes = (method === "GET" || s3Operation === "getObject") ? respBytes : contentLength;

        // 3. Asynchronous DLP Tracking (`ctx.waitUntil`): Track volumetric quotas & rates without blocking client
        if (backendResp.ok || backendResp.status === 304) {
            ctx.waitUntil(trackDlpQuotasAndQuarantine(env, licenseKey, license, method, s3Operation, actualBytes));
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
                path,
                bucket: license.bucket,
                contentLength: actualBytes,
                status: backendResp.status,
                durationMs,
            });

            ctx.waitUntil(writeLog(env, licenseKey, logEntry));
        }

        const respHeaders = new Headers(backendResp.headers);
        respHeaders.set("Access-Control-Allow-Origin", "*");
        respHeaders.set("Access-Control-Allow-Methods", "GET, PUT, DELETE, HEAD, POST, OPTIONS");
        respHeaders.set("Access-Control-Allow-Headers", "*");
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

async function verifyAwsSigV4(request, gatewaySecret, url) {
    try {
        const authHeader = request.headers.get("Authorization");
        const amzDate = request.headers.get("X-Amz-Date") || "";

        const credMatch = authHeader.match(/Credential=([^,]+)/);
        const signedMatch = authHeader.match(/SignedHeaders=([^,]+)/);
        const sigMatch = authHeader.match(/Signature=([a-f0-9]+)/);

        if (!credMatch || !signedMatch || !sigMatch) return false;

        const credentialScope = credMatch[1];
        const signedHeadersStr = signedMatch[1];
        const receivedSig = sigMatch[1];

        const credParts = credentialScope.split("/");
        if (credParts.length < 5) return false;

        const dateStamp = credParts[1];
        const region = credParts[2];
        const service = credParts[3];

        const canonicalQueryString = [...url.searchParams.entries()]
            .sort(([a], [b]) => a < b ? -1 : 1)
            .map(([k, v]) => `${uriEncode(k)}=${uriEncode(v)}`)
            .join("&");

        const payloadHash = request.headers.get("X-Amz-Content-Sha256") || "UNSIGNED-PAYLOAD";
        const signedHeaders = signedHeadersStr.split(";");
        const scope = `${dateStamp}/${region}/${service}/aws4_request`;

        const signingKey = await deriveSigningKey(gatewaySecret, dateStamp, region, service);

        const getNormHeader = (h, overrideVal) => {
            if (overrideVal !== undefined) return overrideVal;
            const raw = request.headers.get(h);
            if (raw === null || raw === undefined) return "";
            return raw.trim().replace(/\s+/g, " ");
        };

        const canPath = url.pathname.split("/").map(seg => {
            try { return uriEncode(decodeURIComponent(seg)); } catch (e) { return uriEncode(seg); }
        }).join("/");
        const pathCandidates = new Set([url.pathname, canPath]);

        const aeVariations = signedHeaders.includes("accept-encoding")
            ? [getNormHeader("accept-encoding"), "gzip", "identity", "gzip, deflate", ""]
            : [undefined];
        const connVariations = signedHeaders.includes("connection")
            ? [getNormHeader("connection"), "keep-alive", "close", ""]
            : [undefined];

        for (const p of pathCandidates) {
            for (const ae of aeVariations) {
                for (const conn of connVariations) {
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
                    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, reqHash].join("\n");
                    const computedSig = await hmacHex(signingKey, stringToSign);

                    if (computedSig === receivedSig) {
                        return true;
                    }
                }
            }
        }

        return false;

    } catch (e) {
        console.error("SigV4 verify error:", e.message);
        return false;
    }
}

async function deriveSigningKey(secret, dateStamp, region, service) {
    const kDate = await hmacRaw(enc("AWS4" + secret), dateStamp);
    const kRegion = await hmacRaw(kDate, region);
    const kService = await hmacRaw(kRegion, service);
    const kSigning = await hmacRaw(kService, "aws4_request");
    return kSigning;
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

async function sha256Hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", enc(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

const enc = (s) => new TextEncoder().encode(s);

async function forwardToBackend(request, originalUrl, targetPath, license, env) {
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
        "aliyuncs.com",
        "myqcloud.com",
        "digitaloceanspaces.com",
        "storage.googleapis.com",
        "linodeobjects.com",
        "exoscale.com",
        "hetzner.com"
    ];

    const preferVirtualHost = license.forceVirtualHost ?? VIRTUAL_HOST_PROVIDERS.some(domain => backendEndpoint.toLowerCase().includes(domain));
    const forcePathStyle = license.forcePathStyle === true;

    if (bucketName && preferVirtualHost && !forcePathStyle) {
        if (!backendEndpoint.toLowerCase().startsWith(bucketName.toLowerCase() + ".")) {
            backendEndpoint = `${bucketName}.${backendEndpoint}`;
        }
        backendPath = targetPath.substring(bucketName.length + 1);
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

    let bodyToForward = (["GET", "HEAD", "DELETE"].includes(request.method) ? null : request.body);
    let actualPayloadHash = payloadHash;
    if (bodyToForward === null && (actualPayloadHash === "UNSIGNED-PAYLOAD" || !actualPayloadHash)) {
        actualPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }

    const isChunkedSigning = payloadHash.startsWith("STREAMING-") ||
        (request.headers.get("content-encoding") || "").includes("aws-chunked") ||
        (request.headers.get("x-amz-content-encoding") || "").includes("aws-chunked");

    if (isChunkedSigning && bodyToForward) {
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

    if (bodyToForward !== null) {
        const bodyBuffer = await new Response(bodyToForward).arrayBuffer();
        cleanHeaders.set("Content-Length", bodyBuffer.byteLength.toString());
        bodyToForward = bodyBuffer;
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
        .map(h => `${h}:${(cleanHeaders.get(h) || "").trim()}`)
        .join("\n") + "\n";

    const canonicalQueryString = [...backendUrl.searchParams.entries()]
        .sort(([a], [b]) => a < b ? -1 : 1)
        .map(([k, v]) => `${uriEncode(k)}=${uriEncode(v)}`)
        .join("&");

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

    const signingKey = await deriveSigningKey(realSecretKey, dateStamp, region, service);
    const signature = await hmacHex(signingKey, stringToSign);

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

    if (method === "GET" && s3Operation !== "getObject") return false;

    if (method === "POST" && !LOGGABLE_POST_ACTIONS.has(s3Operation)) return false;

    return true;
}

function resolveS3Operation(method, path, queryString) {
    const params = new URLSearchParams(queryString.replace("?", ""));

    if (method === "GET") {
        const segments = path.split("/").filter(Boolean);
        if (params.has("list-type") || params.has("delimiter") || params.has("prefix") || segments.length <= 1) return "listObjects";
        if (params.has("tagging")) return "getObjectTagging";
        if (params.has("acl")) return "getObjectAcl";
        if (params.has("versioning")) return "getBucketVersioning";
        if (params.has("lifecycle")) return "getBucketLifecycle";
        if (params.has("policy")) return "getBucketPolicy";
        if (params.has("cors")) return "getBucketCors";
        if (params.has("website")) return "getBucketWebsite";
        if (params.has("replication")) return "getBucketReplication";
        if (params.has("object-lock")) return "getObjectLockConfiguration";
        return "getObject";
    }

    if (method === "DELETE") {
        if (params.has("uploadId")) return "abortMultipartUpload";
        if (params.has("tagging")) return "deleteObjectTagging";
        if (params.has("lifecycle")) return "deleteBucketLifecycle";
        if (params.has("policy")) return "deleteBucketPolicy";
        if (params.has("cors")) return "deleteBucketCors";
        if (params.has("website")) return "deleteBucketWebsite";
        if (params.has("replication")) return "deleteBucketReplication";
        return path.split("/").length > 2 ? "deleteObject" : "deleteBucket";
    }

    if (method === "PUT") {
        if (params.has("tagging")) return "putObjectTagging";
        if (params.has("acl")) return path.split("/").length > 2 ? "putObjectAcl" : "putBucketAcl";
        if (params.has("versioning")) return "putBucketVersioning";
        if (params.has("lifecycle")) return "putBucketLifecycle";
        if (params.has("policy")) return "putBucketPolicy";
        if (params.has("cors")) return "putBucketCors";
        if (params.has("website")) return "putBucketWebsite";
        if (params.has("replication")) return "putBucketReplication";
        if (params.has("object-lock")) return "putObjectLockConfiguration";
        if (params.has("encryption")) return "putBucketEncryption";
        if (params.has("uploadId")) return "uploadPart";
        if (params.has("copySource") || params.get("x-amz-copy-source")) return "copyObject";
        return "putObject";
    }

    if (method === "POST") {
        if (params.has("delete")) return "deleteObjects";
        if (params.has("restore")) return "restoreObject";
        if (params.has("uploads")) return "createMultipartUpload";
        if (params.has("uploadId")) return "completeMultipartUpload";
        return "postObject";
    }

    return `${method.toLowerCase()}Unknown`;
}

// ============================================================
// ============================================================================
// SECURITY POLICY ENGINE (Inline IPS / WAF check)
// ============================================================================

function checkSecurityPolicy(request, url, targetPath, license, s3Operation, sourceIP, country, asn) {
    const sec = license.security_policy || license.securityPolicy || {};

    // 1. IP Denylist and Allowlist Filtering
    const blockedIps = sec.blocked_ips || sec.blockedIps || [];
    if (blockedIps.includes(sourceIP)) {
        return {
            allowed: false,
            status: 403,
            code: "AccessDenied",
            message: "Access blocked by S3GW Security Policy (IP in denylist).",
            blockReason: "IP_DENYLIST",
            riskLevel: "high"
        };
    }

    const allowedIps = sec.allowed_ips || sec.allowedIps || [];
    if (allowedIps.length > 0 && !allowedIps.includes(sourceIP)) {
        return {
            allowed: false,
            status: 403,
            code: "AccessDenied",
            message: "Access blocked by S3GW Security Policy (IP not in allowlist).",
            blockReason: "IP_NOT_ALLOWED",
            riskLevel: "high"
        };
    }

    // 2. Geographic Filtering (Country origin check via Cloudflare Edge)
    const blockedCountries = sec.blocked_countries || sec.blockedCountries || [];
    if (country !== "Unknown" && blockedCountries.map(c => String(c).toUpperCase()).includes(String(country).toUpperCase())) {
        return {
            allowed: false,
            status: 403,
            code: "AccessDenied",
            message: `Access blocked by S3GW Security Policy (Country ${country} is restricted).`,
            blockReason: "GEO_RESTRICTED",
            riskLevel: "high"
        };
    }

    const allowedCountries = sec.allowed_countries || sec.allowedCountries || [];
    if (allowedCountries.length > 0 && country !== "Unknown" && !allowedCountries.map(c => String(c).toUpperCase()).includes(String(country).toUpperCase())) {
        return {
            allowed: false,
            status: 403,
            code: "AccessDenied",
            message: `Access blocked by S3GW Security Policy (Country ${country} is not allowed).`,
            blockReason: "GEO_NOT_ALLOWED",
            riskLevel: "high"
        };
    }

    // 3. ASN / ISP Reputation Filtering (Drop suspicious ASNs or TOR exit nodes)
    const blockedAsns = sec.blocked_asns || sec.blockedAsns || [];
    const numAsn = typeof asn === "number" ? asn : parseInt(String(asn).replace("AS", ""), 10);
    if (!isNaN(numAsn) && blockedAsns.includes(numAsn)) {
        return {
            allowed: false,
            status: 403,
            code: "AccessDenied",
            message: `Access blocked by S3GW Security Policy (ASN ${asn} is restricted).`,
            blockReason: "ASN_BLOCKED",
            riskLevel: "high"
        };
    }

    // 4. Protection des opérations d'Administration (allow_admin_operations)
    const ADMIN_OPERATIONS = new Set([
        "deleteBucket",
        "putBucketVersioning",
        "putBucketLifecycle",
        "deleteBucketLifecycle",
        "putObjectLockConfiguration",
        "putBucketReplication",
        "deleteBucketReplication",
        "putBucketPolicy",
        "deleteBucketPolicy",
        "putBucketAcl",
        "putBucketCors",
        "deleteBucketCors",
        "putBucketWebsite",
        "deleteBucketWebsite",
        "putBucketEncryption"
    ]);

    const allowAdmin = sec.allow_admin_operations !== undefined ? sec.allow_admin_operations :
        (license.allow_admin_operations !== undefined ? license.allow_admin_operations : true);

    if (allowAdmin === false && ADMIN_OPERATIONS.has(s3Operation)) {
        return {
            allowed: false,
            status: 403,
            code: "AccessDenied",
            message: `Administrative operation '${s3Operation}' is forbidden by S3GW security policy on this access key.`,
            blockReason: "ADMIN_OPERATION_FORBIDDEN_BY_GATEWAY_POLICY",
            riskLevel: "high"
        };
    }

    // 5. Ransomware Killswitch & Extension Filtering sur écritures
    const RANSOMWARE_EXTENSIONS = [
        ".locked", ".encrypted", ".ransom", ".crypt", ".lock", ".wannacry",
        ".lockbit", ".crptr", ".crypto", ".enc", ".rnsm"
    ];

    const isPutMutation = ["putObject", "copyObject", "postObject", "uploadPart"].includes(s3Operation);
    if (isPutMutation) {
        const lowerPath = targetPath.toLowerCase();
        for (const ext of RANSOMWARE_EXTENSIONS) {
            if (lowerPath.endsWith(ext) || lowerPath.includes(ext + ".")) {
                const killswitchActive = sec.ransomware_killswitch !== false; // Activé par défaut
                if (killswitchActive) {
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
        }
    }

    return { allowed: true };
}

// ============================================================================
// DLP QUOTAS & QUARANTINE TRACKER (100% KV + Automatic Expiration TTL)
// ============================================================================

async function trackDlpQuotasAndQuarantine(env, licenseKey, license, method, s3Operation, actualBytes) {
    try {
        const sec = license.security_policy || license.securityPolicy || {};
        const quotas = sec.dlp_quotas || sec.dlpQuotas;
        if (!quotas) return;

        const now = new Date();
        const ymd = now.toISOString().split("T")[0]; // YYYY-MM-DD
        const hour = now.getUTCHours();
        const minute = now.getUTCMinutes();

        const quarantineDuration = quotas.quarantine_duration_seconds || 3600;

        // 1. Download Volumetric Exfiltration Quota (Bytes per hour)
        if ((method === "GET" || s3Operation === "getObject") && actualBytes > 0 && quotas.max_download_bytes_per_hour) {
            const hourKey = `dlp:${licenseKey}:bytes:${ymd}-${hour}`;
            const currentStr = await env.LICENSES_KV.get(hourKey);
            const currentBytes = parseInt(currentStr || "0", 10);
            const newTotal = currentBytes + actualBytes;

            await env.LICENSES_KV.put(hourKey, newTotal.toString(), { expirationTtl: 7200 }); // TTL 2h

            if (newTotal > quotas.max_download_bytes_per_hour) {
                await env.LICENSES_KV.put(`quarantine:${licenseKey}`, JSON.stringify({
                    reason: "QUOTA_EXFILTRATION_BYTES_EXCEEDED",
                    bytes_downloaded: newTotal,
                    limit: quotas.max_download_bytes_per_hour,
                    quarantined_at: now.toISOString()
                }), { expirationTtl: quarantineDuration });
            }
        }

        // 2. GET Request Rate Quota per Minute (Anti-scraping / bulk scan protection)
        if ((method === "GET" || s3Operation === "getObject" || s3Operation === "listObjects") && quotas.max_get_requests_per_minute) {
            const minKey = `dlp:${licenseKey}:get:${ymd}-${hour}-${minute}`;
            const currentStr = await env.LICENSES_KV.get(minKey);
            const currentReqs = parseInt(currentStr || "0", 10);
            const newReqs = currentReqs + 1;

            await env.LICENSES_KV.put(minKey, newReqs.toString(), { expirationTtl: 300 }); // TTL 5m

            if (newReqs > quotas.max_get_requests_per_minute) {
                await env.LICENSES_KV.put(`quarantine:${licenseKey}`, JSON.stringify({
                    reason: "QUOTA_GET_REQUESTS_PER_MINUTE_EXCEEDED",
                    requests_count: newReqs,
                    limit: quotas.max_get_requests_per_minute,
                    quarantined_at: now.toISOString()
                }), { expirationTtl: quarantineDuration });
            }
        }

        // 3. DELETE Request Rate Quota per Minute (Anti-wiper / mass destruction protection)
        if ((method === "DELETE" || s3Operation.includes("delete")) && quotas.max_delete_requests_per_minute) {
            const minKey = `dlp:${licenseKey}:del:${ymd}-${hour}-${minute}`;
            const currentStr = await env.LICENSES_KV.get(minKey);
            const currentReqs = parseInt(currentStr || "0", 10);
            const newReqs = currentReqs + 1;

            await env.LICENSES_KV.put(minKey, newReqs.toString(), { expirationTtl: 300 }); // TTL 5m

            if (newReqs > quotas.max_delete_requests_per_minute) {
                await env.LICENSES_KV.put(`quarantine:${licenseKey}`, JSON.stringify({
                    reason: "QUOTA_DELETE_REQUESTS_PER_MINUTE_EXCEEDED",
                    requests_count: newReqs,
                    limit: quotas.max_delete_requests_per_minute,
                    quarantined_at: now.toISOString()
                }), { expirationTtl: quarantineDuration });
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
    if (["putObject", "copyObject", "uploadPart", "postObject"].includes(s3Operation)) flags.push("write_operation");
    if (s3Operation === "getObject") flags.push("read_operation");
    if (s3Operation === "putObjectTagging") flags.push("tagging_change");
    if (s3Operation.includes("Lifecycle") || s3Operation.includes("Versioning") || s3Operation.includes("ObjectLock")) flags.push("lifecycle_change");
    if (status >= 400) flags.push("error_response");
    if (status === 403) flags.push("access_denied");
    if (status === 429) flags.push("dlp_quarantine_blocked");

    let action = "allowed";
    let blockReason = null;
    let riskLevel =
        flags.includes("delete_operation") ? "high" :
            flags.includes("write_operation") ? "medium" :
                flags.includes("error_response") ? "low" : "info";

    if (securityDecision && !securityDecision.allowed) {
        action = "blocked";
        blockReason = securityDecision.blockReason || "SECURITY_POLICY_VIOLATION";
        riskLevel = securityDecision.riskLevel || "high";
        flags.push("security_policy_blocked");
        if (blockReason) flags.push(blockReason.toLowerCase());
    }

    const keyPath = path.replace(/^\/[^/]+\//, "/");

    return {
        ts: new Date().toISOString(),
        licence: licenseKey,
        gateway: {
            host: gwHost || "s3gw.yourdomain.com",
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

async function writeLog(env, licenseKey, logEntry) {
    try {
        const now = new Date();
        const year = now.getUTCFullYear();
        const month = String(now.getUTCMonth() + 1).padStart(2, "0");
        const day = String(now.getUTCDate()).padStart(2, "0");
        const ts = now.getTime();
        const shortKey = licenseKey.substring(0, 8);

        const r2Path = `${licenseKey}/${year}/${month}/${day}/log${shortKey}${ts}.json`;

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
        return '%' + c.charCodeAt(0).toString(16).toUpperCase();
    });
}

function errorResponse(status, code, message, gwHost = "s3gw.yourdomain.com") {
    const reqId = "s3gw-" + Math.random().toString(36).substring(2, 11);
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>${code}</Code>
  <Message>${message}</Message>
  <RequestId>${reqId}</RequestId>
  <HostId>${gwHost}</HostId>
</Error>`;
    return new Response(xml, {
        status,
        headers: {
            "Content-Type": "application/xml",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, PUT, DELETE, HEAD, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Cache-Control": "no-transform",
        },
    });
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
