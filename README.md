# S3GW — Universal S3 Gateway at the Edge with Logging, Firewall & IPS Proxy capabilities

[![Website](https://img.shields.io/badge/Website-s3gw.com-F0B429?labelColor=171310&style=flat-square)](https://s3gw.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-F0B429?labelColor=171310&style=flat-square)](https://opensource.org/licenses/MIT)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-Ready-F0B429?labelColor=171310&logo=cloudflare&logoColor=171310&style=flat-square)](https://workers.cloudflare.com/)
[![Built by SIENNA](https://img.shields.io/badge/Built%20by-SIENNA%20IT%20Solutions-F0B429?labelColor=171310&style=flat-square)](https://sienna.dev)
[![tamper Module](https://img.shields.io/badge/Core%20Module%20for-tamper-F0B429?labelColor=171310&style=flat-square)](https://tamper.fr)

**S3GW** is an open-source, provider-agnostic **Cybersecurity Reverse-Proxy and Active Threat Firewall for the S3 protocol**. Executing with **0ms sequential overhead** on Cloudflare Workers (Anycast Edge across 300+ global cities), S3GW sits transparently between your applications/backup agents and your real object storage provider.

Whether your buckets are hosted on **AWS S3, Cloudflare R2, Scaleway, Hetzner, OVHcloud, Wasabi, or Google Cloud Storage**, S3GW provides real-time access control, behavioral threat blocking, data exfiltration quotas, and enriched JSON audit logging—**without requiring any modifications to your S3 client SDKs or applications**.

---

## Why S3GW?

Legacy S3 buckets are vulnerable to **stolen access keys**, **overnight data exfiltration**, **ransomware encryption**, and **mass deletion (wipers)**. Native IAM policies are complex, provider-dependent, and lack instant edge geo-blocking or volumetric rate limits.

S3GW solves this by introducing **IAM Virtualization & Perimeter Defense**:
- **100% S3 Transparent Proxying:** Validates AWS Signature V4 on the edge, applies security policies in `<0.1ms`, and resigns requests toward the real cloud provider.
- **Provider Agnostic & Zero-Vendor Lock-in:** Separate your perimeter security from your storage vendor (`Separation of Duties`).
- **Zero Egress Latency:** Asynchronous logging (`ctx.waitUntil`) and parallel KV caching (`Promise.all`) ensure zero performance degradation.

---

## Key Features & The 2 Pillars of Active Cyber Defense

### Pillar 1: Active Threat Blocking & Security Policy Engine (Inline IPS/WAF)
Every access key can be hardened with precise behavioral restrictions:
- **Strict Target Bucket Validation:** Every request is tightly validated against the exact bucket authorized in the KV license. Any mismatch or global listing attempt triggers an instant 403.
- **Geo-Blocking & ASN Reputation:** Whitelist/Denylist specific countries (`allowed_countries`, `blocked_countries`), ISPs, or Autonomous Systems (`blocked_asns`).
- **IP Denylists / Whitelists:** Instantly drop traffic from suspicious or unauthorized IP ranges.
- **Ransomware Extension Killswitch (`PUT` Inspection):** Automatically detects and drops file uploads with known ransomware extensions. Now built-in with over 50 of the most active ransomware extensions (LockBit, Conti, BlackCat, Akira, Phobos, etc.) and supports custom extension blocklists per license.
- **Administrative Operation Prohibition:** Block bucket-destroying or security-disabling operations (`deleteBucket`, `putBucketVersioning` suspended, `putBucketLifecycle` deletion) even if the underlying cloud API key has admin privileges (`allow_admin_operations: false`).

### Pillar 2: Data Exfiltration Prevention (DLP Volumetric Quotas & Auto-Quarantine)
Defend against stolen logic access keys being used to download entire data lakes overnight:
- **Hourly Download Volumetric Quota:** Set exact byte limits (`max_download_bytes_per_hour`).
- **Rate Limiting (`GET` & `DELETE`):** Prevent automated scraping or mass deletion (`max_get_requests_per_minute`, `max_delete_requests_per_minute`).
- **Ephemeral KV Quarantine (`Auto-Cleaning`):** When a threshold is exceeded, S3GW places the key in quarantine (`quarantine:ACCESS_KEY`) with an exact `expirationTtl`. The gateway immediately returns `<Error><Code>SlowDown</Code><Message>...</Message></Error>` (HTTP 429) until the TTL expires, requiring **no manual intervention or background cron jobs**.

---

## Enriched SIEM JSON Audit Logging (`V2 Specification`)

Every single request—whether allowed, geo-blocked, or quarantined—is asynchronously recorded as an immutable JSON audit file into a Cloudflare R2 bucket (`R2_GATEWAY`). To ensure a high signal-to-noise ratio, all critical actions and data access (`GET`, `PUT`, `DELETE`, listings) are fully logged, while passive metadata reads (`HEAD`) are intentionally ignored to prevent noise.

### Directory Partitioning Structure in R2:
```text
[licenseKey]/YYYY/MM/DD/log[8chars][timestamp].json
```

### Example Log Entry (Ingestion-Ready for Splunk, Datadog, Elastic Security, or Wazuh):
```json
{
  "ts": "2026-07-11T19:48:05.892Z",
  "licence": "S3GW_CLIENT_PROD_01",
  "gateway": {
    "host": "s3gw.yourdomain.com",
    "ip": "185.220.101.5",
    "country": "RU",
    "city": "Moscow",
    "asn": 24940,
    "as_organization": "Hetzner Online GmbH",
    "user_agent": "aws-cli/2.15.0 Python/3.11.6 Linux/x86_64",
    "access_key_used": "S3GW_CLIENT_PROD_01"
  },
  "operation": {
    "method": "GET",
    "type": "getObject",
    "bucket": "customer-prod-data",
    "key": "/database/backup_prod.sql"
  },
  "response": {
    "status": 403,
    "bytes": 0,
    "duration_ms": 14
  },
  "security": {
    "action": "blocked",
    "risk_level": "high",
    "block_reason": "GEO_RESTRICTED",
    "flags": ["read_operation", "access_denied", "geo_restricted", "security_policy_blocked"]
  }
}
```

---

## 5-Minute Deployment Guide on Cloudflare Workers

### 1. Prerequisites
- A Cloudflare account with Workers, KV, and R2 enabled.
- Node.js and [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) installed (`npm install -g wrangler`).

### 2. Create Resources & Clone Repository
First, create your Cloudflare KV namespace and R2 bucket using Wrangler:
```bash
# Create KV Namespace for licenses & quotas
wrangler kv namespace create LICENSES_KV

# Create R2 Bucket for real-time audit logs
wrangler r2 bucket create s3gw-audit-logs
```

Then, clone this MIT repository and configure your bindings:
```bash
git clone https://github.com/SIENNA-IT-Solutions/s3gw.git
cd s3gw
cp wrangler.toml.example wrangler.toml
```

Edit `wrangler.toml` with the IDs generated above:
```toml
name = "s3gw-firewall"
main = "s3gwGateway.js"
compatibility_date = "2026-07-11"

[vars]
GATEWAY_HOST = "s3gw.yourdomain.com" # Or your Cloudflare Worker domain (e.g. s3gw.my-tenant.workers.dev)

[[kv_namespaces]]
binding = "LICENSES_KV"
id = "YOUR_CLOUDFLARE_KV_NAMESPACE_ID"

[[r2_buckets]]
binding = "R2_GATEWAY"
bucket_name = "s3gw-audit-logs"
```

### 3. Deploy to Cloudflare Edge
```bash
wrangler deploy
```

### 4. Add Your First Client License in Cloudflare KV
In your `LICENSES_KV` namespace, create a new key where **Key Name** = `TGW_DEMO_S3GW_KEY` (the logical `access_key` your client will use), and **Value** = the contents of [`s3gwLicence.json`](./s3gwLicence.json).

> [!IMPORTANT]
> **Self-Hosted & Zero-Trust Architecture:** You deploy and run S3GW inside **your own Cloudflare account**. Your real AWS/R2 secret keys (`LICENSES_KV`) and audit logs (`R2_GATEWAY`) stay 100% inside your private Cloudflare tenant (`Self-Hosted`). You **never** send your credentials to SIENNA or to any third party.

Now, point any S3 tool (AWS CLI, Cyberduck, Veeam, rclone) to `https://s3gw.yourdomain.com/your-bucket` using `TGW_DEMO_S3GW_KEY` as Access Key and its `secret_key`!

---

## The Bridge to tamper — Deep S3 Object Security & FIM

S3GW excels at perimeter defense (`North-South traffic interception`) at the network edge. But what happens if:
- An attacker bypasses the gateway proxy directly to your underlying cloud provider (`East-West` or root credential compromise)?
- A legitimate access key or application silently corrupts files, uploads poisoned payloads, or modifies critical metadata?
- You require compliance-grade **File Integrity Monitoring (FIM)**, continuous cryptographic verification (`SHA-256/BLAKE3`), automated threat forensics, and centralized SOC dashboards without building custom SIEM parsers?

**Discover [tamper](https://tamper.fr)** — our professional SaaS cybersecurity platform specifically engineered for **S3 Object Storage Data Integrity, File Integrity Monitoring (FIM), and Cloud Detection & Response (CDR)**.

S3GW natively integrates with **tamper**: connect your S3GW audit buckets to tamper to unlock instant visual dashboards, real-time SOC alerts (`Slack / Teams / PagerDuty / Datadog`), and automated deep-object verification across all your clouds.

---

## Contributing & Open-Source Community

We love open-source! If you find **S3GW** useful:
1. **Star this repository** to support our research in open-source cloud security.
2. **Fork & Build:** Feel free to create your own implementation or port the S3GW logic to your favorite language (**Go, Rust, Python, TypeScript**).
3. **Submit PRs:** Found a bug, want to add new DLP detection rules or webhook exporters? Pull requests are warmly welcomed!

---

## License & Credits

Developed by **[SIENNA](https://sienna.dev)** (`tamper` team).  
Released under the **[MIT License](./LICENSE)**. Free to use, modify, and distribute for commercial and private projects.
