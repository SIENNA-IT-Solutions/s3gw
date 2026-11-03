# S3GW — Universal Cloudflare Edge S3 Firewall, IPS & Cloaking Proxy

[![Website](https://img.shields.io/badge/Website-s3gw.com-F0B429?labelColor=171310&style=flat-square)](https://s3gw.com)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-F0B429?labelColor=171310&style=flat-square)](./LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-Ready-F0B429?labelColor=171310&logo=cloudflare&logoColor=171310&style=flat-square)](https://workers.cloudflare.com/)
[![Built by SIENNA](https://img.shields.io/badge/Built%20by-SIENNA%20IT%20Solutions-F0B429?labelColor=171310&style=flat-square)](https://sienna.dev)
[![tamper Module](https://img.shields.io/badge/Core%20Module%20for-tamper-F0B429?labelColor=171310&style=flat-square)](https://tamper.fr)

**S3GW** is an open-source, On-Prem/DIY cybersecurity gateway built for **DevOps, DevSecOps, Cloud Engineers, and SOC teams**. Running at the Cloudflare Edge with **<5ms overhead**, S3GW acts as a transparent S3 reverse-proxy, an inline Threat Firewall (IPS), a Zero-Exposure Presigned URL Cloaking Engine, and a real-time SIEM audit logger.

Whether you manage 1 or 100 buckets across **AWS S3, Cloudflare R2, Scaleway, OVHcloud, Leviia, Wasabi, Hetzner, or Backblaze B2**, a **single S3GW Worker** routes, inspects, and translates every request using isolated per-bucket KV policies—**without exposing your real S3 endpoints, bucket names, or cloud IAM keys**.

---

## Core Architecture: 1 Worker, $N$ Buckets, Multi-Cloud Isolation

```
[ S3 SDK / CLI / Terraform / Browser ]
                 │
                 ▼  (Virtual Gateway Keys OR Cloaked /dl/<token> Link)
     ┌───────────────────────┐
     │   S3GW Edge Worker    │ ◄─── Cloudflare KV (1 Entry per Bucket)
     │  • SigV4 & AES-256    │      • Virtual Keys <-> Real Provider Keys
     │  • Geo/ASN/IP/UA IPS  │      • Ransomware Killswitch & Admin Lock
     │  • DLP Quotas & Guard │      • Presigned URL Policy & Single-Use
     └──────────┬────────────┘
                ├──────────────────► R2 SIEM Audit Bucket (Async JSON Logs)
                ▼
[ AWS S3 | Scaleway | OVH | R2 | Wasabi | Leviia ] (100% Private & Cloaked)
```

---

## The 3 Pillars of Active S3 Cyber Defense

### Pillar 1: Inline S3 Firewall & IPS (Zero-Trust Perimeter)
Every virtual access key is hardened at the Edge before traffic ever reaches your storage provider:
- **Strict Bucket & Copy-Source Isolation:** Blocks unauthorized bucket access and cross-bucket `x-amz-copy-source` exfiltration attempts.
- **Recursive Path Normalization:** Decodes multi-pass URI encodings (`%252e%252e`) to block path traversal attacks (`400 InvalidURI`).
- **IPv4 / IPv6 & CIDR Filtering:** Full support for IPv4, canonicalized IPv6, IPv4-mapped IPv6 (`::ffff:0:0/96`), and CIDR ranges.
- **Geo-Fencing & ASN Reputation:** Allowlist or denylist countries (`FR`, `DE`) and Autonomous Systems (`blocked_asns`).
- **Ransomware Extension Killswitch (`PUT` / `POST` Inspection):** Inspects single and multipart uploads to block 55+ known ransomware extensions (`.lockbit`, `.blackcat`, `.encrypted`, compound extensions like `report.pdf.lockbit.id123`) plus custom extension allow/denylists.
- **Administrative Operation Lock (`allow_admin_operations: false`):** Prevents bucket deletion, policy/ACL tampering, lifecycle modification, or versioning suspension even if the backend S3 key has full permissions.
- **Streaming `aws-chunked` Decoder & GUI Compatibility:** Natively decodes `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and serves synthetic `ListAllMyBucketsResult` on `GET /` so Cyberduck, S3 Browser, WinSCP, Veeam, and rclone work out-of-the-box.

### Pillar 2: Zero-Exposure Cloaked Presigned URLs (`/dl/` & `/s/`)
Standard S3 presigned URLs leak your cloud provider (`amazonaws.com`), your region, your internal bucket name, and your object hierarchy, and **cannot be revoked** once issued. S3GW replaces them with **Cloaked Presigned URLs**:
- **AES-256-GCM Encrypted Tokens (`v1e.`):** Mint temporary download/upload links (`https://gateway.domain.tld/dl/v1e...`) where the object key, expiration, and metadata are encrypted with WebCrypto `AES-256-GCM`. Even base64 decoding reveals zero internal paths or bucket names.
- **Stateless HMAC Tokens (`v1.`):** Generate signed links locally in 0ms from any microservice, Python script, or Ansible playbook without calling the gateway.
- **Standard AWS SigV4 Query Support (`?X-Amz-Signature=...`):** Drop-in compatibility with `aws s3 presign` and `boto3` presigned URLs (supports `/_/path/to/object` alias to hide the bucket name).
- **Single-Use Links (`single_use: true`):** Automatically invalidates the link after the first successful download (`200`/`206`), blocking replay or link-sharing abuse (`403 SINGLE_USE_TOKEN_ALREADY_CONSUMED`).
- **Client IP / CIDR Binding (`ip_bind`):** Cryptographically locks a presigned link to the recipient's IP or subnet (`403 TOKEN_IP_MISMATCH`).
- **Response Header Cloaking (`cloak_backend_headers: true`):** Strips provider-identifying headers (`x-amz-request-id`, `x-amz-id-2`, `x-scw-*`, `x-ovh-*`, `Server: AmazonS3`) and replaces them with `Server: s3gw`.

### Pillar 3: DLP Volumetric Quotas & Auto-Quarantine
- **Hourly Exfiltration Cap (`max_download_bytes_per_hour`):** Stops mass data theft in real time.
- **Anti-Scraping & Anti-Wiper Rate Limits:** Enforces `max_get_requests_per_minute` and batch-aware `max_delete_requests_per_minute` (parses XML `<Object>` count inside `POST ?delete` batches before forwarding).
- **Instant Isolate + KV Quarantine:** Exceeding any threshold triggers an immediate `429 SlowDown` quarantine across both the isolate LRU memory cache (0ms blind window) and Cloudflare KV (`quarantine:<key>` and `quarantine:<key>:<ip>`).

---

## DevOps & DevSecOps How-To Guide

### Step 1: Deploy the Worker (5 Minutes)

```bash
# 1. Create the KV namespace (stores bucket licenses & optional DLP counters)
wrangler kv namespace create LICENSES_KV

# 2. Create the R2 bucket (stores immutable JSON SIEM audit logs)
wrangler r2 bucket create s3gw-audit-logs

# 3. Configure wrangler.toml
cp wrangler.toml.example wrangler.toml
```

Edit `wrangler.toml`:
```toml
name = "s3gw-firewall"
main = "s3gwGateway.js"
compatibility_date = "2026-07-11"

[vars]
GATEWAY_HOST = "gateway.yourdomain.com"
# Optional: set to "true" for Zero-KV-Write mode (disables DLP KV writes)
DISABLE_DLP_KV_WRITES = "false"
# Optional: global CORS origins fallback
CORS_ALLOWED_ORIGINS = ""

[[kv_namespaces]]
binding = "LICENSES_KV"
id = "YOUR_CLOUDFLARE_KV_NAMESPACE_ID"

[[r2_buckets]]
binding = "R2_GATEWAY"
bucket_name = "s3gw-audit-logs"
```

Deploy to Cloudflare Edge:
```bash
wrangler deploy
```

---

### Step 2: Provision Bucket Licenses in KV (1 KV Entry = 1 Bucket)

In `LICENSES_KV`, each bucket is configured as a JSON document where the **KV Key** is the virtual `gateway.access_key` (e.g., `GW_MR_PROD_01`). Lookups are cached in a bounded in-memory LRU cache (`60s` TTL) for near-zero latency.

Save `s3gwLicence.json`:
```json
{
  "activated": true,
  "expires_at": "2099-12-31T23:59:59Z",
  "bucket": "mr-labels-internal-prod",
  "gateway": {
    "enabled": true,
    "access_key": "GW_MR_PROD_01",
    "secret_key": "YOUR_GATEWAY_VIRTUAL_SECRET_KEY",
    "cloak_backend_headers": true,
    "presigned_urls": {
      "enabled": true,
      "allow_encrypted_tokens": true,
      "allow_hmac_tokens": true,
      "allow_sigv4_query": true,
      "allow_bearer_minting": true,
      "default_ttl_seconds": 900,
      "max_ttl_seconds": 86400,
      "enforce_single_use": false,
      "allowed_methods": ["GET", "HEAD"]
    }
  },
  "accessKey": "AKIA_REAL_PROVIDER_ACCESS_KEY",
  "secretKey": "REAL_PROVIDER_SECRET_KEY",
  "endpoint": "s3.eu-west-3.amazonaws.com",
  "region": "eu-west-3",
  "forceVirtualHost": true,
  "forcePathStyle": false,
  "security_policy": {
    "allowed_countries": ["FR", "BE", "DE", "CH"],
    "blocked_countries": ["RU", "CN", "KP", "IR"],
    "allowed_ips": [],
    "blocked_ips": ["185.220.101.0/24"],
    "allowed_asns": [],
    "blocked_asns": [4134, 4837],
    "allowed_user_agents": [],
    "blocked_user_agents": ["sqlmap", "nikto"],
    "allowed_extensions": [],
    "blocked_extensions": [".exe", ".sh"],
    "allow_admin_operations": false,
    "ransomware_killswitch": true,
    "dlp_quotas": {
      "max_download_bytes_per_hour": 10737418240,
      "max_get_requests_per_minute": 600,
      "max_delete_requests_per_minute": 60,
      "quarantine_duration_seconds": 3600
    }
  }
}
```

Push the license to Cloudflare KV via Wrangler CLI:
```bash
wrangler kv key put --binding=LICENSES_KV "GW_MR_PROD_01" --path=s3gwLicence.json
```

> [!TIP]
> **Zero-KV-Write Mode (for High-Throughput DAM & tamper Integration)**
> To run S3GW with **zero KV writes** (100% read-only on KV), set `"dlp_quotas": false` (or `"disable_dlp_kv_writes": true` in the license JSON, or `DISABLE_DLP_KV_WRITES = "true"` in `wrangler.toml`). All inline IPS rules (GeoIP, IP/CIDR allow/denylists, ASN, User-Agent, Ransomware Killswitch, Admin Lock) and R2 SIEM logging remain 100% active without generating a single KV write operation.

---

### Step 3: How to Use S3GW in Your Workflows

#### A. Standard S3 CLI, SDKs, Terraform & Backup Tools
Configure your S3 client to use `https://gateway.yourdomain.com` with your virtual `gateway.access_key` and `gateway.secret_key`:

```bash
export AWS_ACCESS_KEY_ID="GW_MR_PROD_01"
export AWS_SECRET_ACCESS_KEY="YOUR_GATEWAY_VIRTUAL_SECRET_KEY"
export AWS_DEFAULT_REGION="eu-west-3"

# Upload an object through the S3GW Firewall
aws s3 cp ./shipping-label-994812.pdf s3://mr-labels-internal-prod/bordereaux/2026/colis-994812.pdf \
  --endpoint-url https://gateway.yourdomain.com
```

#### B. Minting Zero-Exposure Cloaked Presigned Links (`POST /_s3gw/presign`)
Instead of exposing direct S3 presigned URLs to customers (e.g., e-commerce invoices, parcel shipping labels, confidential reports), call `POST /_s3gw/presign` using either `Authorization: Bearer <access_key>:<secret_key>` or AWS SigV4:

```bash
curl -s -X POST https://gateway.yourdomain.com/_s3gw/presign \
  -H "Authorization: Bearer GW_MR_PROD_01:YOUR_GATEWAY_VIRTUAL_SECRET_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "bordereaux/2026/colis-994812.pdf",
    "expires_in": 900,
    "single_use": true,
    "ip_bind": "203.0.113.0/24",
    "filename": "bon-envoi-994812.pdf",
    "correlation_id": "lbc-order-994812",
    "mode": "encrypted"
  }'
```

**Response:**
```json
{
  "url": "https://gateway.yourdomain.com/dl/v1e.R1dfTVJfUFJPRF8wMQ.XGY6l8AAFY1iPxLaZnzQ...",
  "token": "v1e.R1dfTVJfUFJPRF8wMQ.XGY6l8AAFY1iPxLaZnzQ...",
  "mode": "encrypted",
  "method": "GET",
  "expires_in": 900,
  "expires_at": "2026-11-03T17:17:28.000Z",
  "single_use": true,
  "ip_bind": "203.0.113.0/24",
  "jti": "a7120e9545c28dc6",
  "correlation_id": "lbc-order-994812"
}
```

When the end-user opens `https://gateway.yourdomain.com/dl/v1e...` in their browser or via `curl`:
1. S3GW decrypts the `AES-256-GCM` token and verifies expiration, IP binding, single-use status, and security policies.
2. S3GW signs a real S3 `GET` request to `mr-labels-internal-prod.s3.eu-west-3.amazonaws.com` on the fly.
3. S3GW strips all AWS headers (`x-amz-*`, `Server: AmazonS3`) and streams the PDF with `Content-Disposition: attachment; filename="bon-envoi-994812.pdf"`.

#### C. Offline / Local Stateless Token Generation (Python / Ansible / CI)
Need to generate millions of links locally without an HTTP call to `/_s3gw/presign`? Use `v1` HMAC tokens in 10 lines of Python:

```python
import hmac, hashlib, json, time, base64, secrets

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def generate_offline_s3gw_url(gateway_url: str, access_key: str, secret_key: str, object_key: str, ttl: int = 900, correlation_id: str = None):
    now = int(time.time())
    payload = {"k": object_key, "m": "GET", "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8)}
    if correlation_id:
        payload["cid"] = correlation_id
    ak_b64 = b64u(access_key.encode())
    pl_b64 = b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"v1.{ak_b64}.{pl_b64}".encode()
    derived_key = hmac.new(b"S3GW_CLOAK_HMAC_V1", secret_key.encode(), hashlib.sha256).digest()
    sig_b64 = b64u(hmac.new(derived_key, signing_input, hashlib.sha256).digest())
    return f"{gateway_url.rstrip('/')}/dl/v1.{ak_b64}.{pl_b64}.{sig_b64}"
```

---

## Enriched SIEM JSON Audit Logging & SOC Correlation

Every request (API call, presigned token mint, cloaked download, or blocked attack) is asynchronously written to R2 (`[licenseKey]/YYYY/MM/DD/log[8chars][ts]_[rand].json`):

```json
{
  "ts": "2026-11-03T17:02:25.104Z",
  "licence": "GW_MR_PROD_01",
  "gateway": {
    "host": "gateway.yourdomain.com",
    "ip": "203.0.113.42",
    "country": "FR",
    "city": "Paris",
    "asn": 3215,
    "as_organization": "Orange SA",
    "user_agent": "Mozilla/5.0",
    "access_key_used": "GW_MR_PROD_01",
    "auth_mode": "cloaked_token_encrypted"
  },
  "operation": {
    "method": "GET",
    "type": "getObject",
    "bucket": "mr-labels-internal-prod",
    "key": "/bordereaux/2026/colis-994812.pdf"
  },
  "response": {
    "status": 200,
    "bytes": 148920,
    "duration_ms": 38
  },
  "security": {
    "action": "allowed",
    "risk_level": "info",
    "block_reason": null,
    "flags": [
      "read_operation",
      "presigned_access",
      "cloaked_token_encrypted",
      "single_use_token",
      "ip_bound_token"
    ]
  },
  "correlation": {
    "token_jti": "a7120e9545c28dc6",
    "correlation_id": "lbc-order-994812",
    "single_use": true,
    "ip_bound": "203.0.113.0/24"
  }
}
```

---

## Native Integration with tamper (FIM + DSPM + DAM + DLP)

S3GW is the edge engine powering **[tamper](https://tamper.fr)**'s Data Access Monitoring (DAM). Connect your `R2_GATEWAY` bucket to tamper to correlate real-time S3 access logs (`who`, `when`, `from where`, `correlation_id`) with File Integrity Monitoring (FIM) and AI-powered DLP content inspection.

---

## License & Credits

Developed by **[SIENNA](https://sienna.dev)** (creators of [tamper](https://tamper.fr)).
Released under the **[Business Source License 1.1 (BSL)](./LICENSE)** — free for internal On-Prem/DIY infrastructure usage by Developers, DevOps, and DevSecOps teams.
