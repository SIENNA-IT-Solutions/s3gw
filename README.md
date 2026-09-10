# S3GW — Universal Cloudflare Edge S3 Firewall & IPS Proxy

[![Website](https://img.shields.io/badge/Website-s3gw.com-F0B429?labelColor=171310&style=flat-square)](https://s3gw.com)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-F0B429?labelColor=171310&style=flat-square)](./LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-Ready-F0B429?labelColor=171310&logo=cloudflare&logoColor=171310&style=flat-square)](https://workers.cloudflare.com/)
[![Built by SIENNA](https://img.shields.io/badge/Built%20by-SIENNA%20IT%20Solutions-F0B429?labelColor=171310&style=flat-square)](https://sienna.dev)
[![tamper Module](https://img.shields.io/badge/Core%20Module%20for-tamper-F0B429?labelColor=171310&style=flat-square)](https://tamper.fr)

**S3GW** is an open-source, free, On-Prem/DIY cybersecurity product explicitly designed for **Developers, DevSecOps, and DevOps**. Executing with **0ms sequential overhead** on Cloudflare Workers, S3GW acts as a transparent reverse-proxy and Active Threat Firewall for the S3 protocol.

Whether your buckets are hosted on **AWS S3, Cloudflare R2, Scaleway, Hetzner, OVHcloud, Wasabi, or Google Cloud Storage**, S3GW provides real-time access control, behavioral threat blocking, data exfiltration quotas, and enriched JSON audit logging—**without requiring any modifications to your S3 client SDKs or applications**.

---

## Why S3GW for DevSecOps?

Legacy S3 buckets are vulnerable to **stolen access keys**, **overnight data exfiltration**, **ransomware encryption**, and **mass deletion (wipers)**. Native IAM policies are complex, provider-dependent, and lack instant edge geo-blocking or volumetric rate limits.

S3GW empowers Developers and DevSecOps teams to build their own Zero-Trust perimeter:
- **DIY & On-Prem (Cloudflare Edge):** Run it inside your own Cloudflare account. Your credentials and audit logs never leave your infrastructure.
- **Provider Agnostic:** Secure AWS, R2, or any S3-compatible storage with a unified, code-driven configuration.
- **Zero Egress Latency:** Asynchronous logging (`ctx.waitUntil`) and parallel KV caching (`Promise.all`) ensure zero performance degradation.

---

## Key Features & The 2 Pillars of Active Cyber Defense

### Pillar 1: Active Threat Blocking & Security Policy Engine (Inline IPS/WAF)
Every access key can be hardened with precise behavioral restrictions enforced at the Edge:
- **Strict Target Bucket Validation:** Mismatches trigger an instant 403.
- **Geo-Blocking & ASN Reputation:** Whitelist/Denylist specific countries, ISPs, or Autonomous Systems (`blocked_asns`).
- **IP Denylists / Whitelists:** Instantly drop traffic from suspicious IPs.
- **User-Agent Filtering:** Allow or block specific client tools.
- **Ransomware Extension Killswitch (`PUT` Inspection):** Automatically detects and drops file uploads with known ransomware extensions (LockBit, Conti, BlackCat, etc.). Supports custom extensions.
- **Administrative Operation Prohibition:** Block bucket-destroying operations (e.g., `deleteBucket`, lifecycle changes, versioning suspension) even if the underlying cloud API key has admin privileges (`allow_admin_operations: false`).

### Pillar 2: Data Exfiltration Prevention (DLP Volumetric Quotas & Auto-Quarantine)
Defend against stolen logic access keys:
- **Hourly Download Volumetric Quota:** Set exact byte limits (`max_download_bytes_per_hour`).
- **Rate Limiting (`GET` & `DELETE`):** Prevent automated scraping or mass deletion (`max_get_requests_per_minute`, `max_delete_requests_per_minute`).
- **Ephemeral KV Quarantine (`Auto-Cleaning`):** When a threshold is exceeded, S3GW automatically places the key in quarantine with a TTL. The gateway immediately returns an HTTP 429 `SlowDown` until the TTL expires—no cron jobs required.

---

## Enriched SIEM JSON Audit Logging & Correlation

Every single request is asynchronously recorded as an immutable JSON audit file into a Cloudflare R2 bucket (`R2_GATEWAY`). 
These enriched logs are specifically designed to **feed your SIEM, SOC, and other cybersecurity solutions for advanced event correlation** (Splunk, Sentinel, Datadog, Wazuh, etc.).

**Directory Partitioning Structure in R2:**
```text
[licenseKey]/YYYY/MM/DD/log[8chars][timestamp].json
```

### Example Log Entry (Ingestion-Ready for Splunk, Datadog, or Elastic Security):

**[Example: PUT Operation - File Upload]**
```json
{
  "ts": "2026-07-04T19:45:12.304Z",
  "licence": "DEMO_S3GW_KEY",
  "gateway": {
    "ip": "81.252.14.99",
    "country": "FR",
    "city": "Paris",
    "asn": "AS3215",
    "as_organization": "Orange SA",
    "user_agent": "aws-cli/2.15.0 Python/3.11.6 Linux/5.10.0-8-amd64",
    "access_key_used": "DEMO_S3GW_KEY"
  },
  "operation": {
    "method": "PUT",
    "type": "putObject",
    "bucket": "my-target-bucket",
    "key": "/reports/2026_Q3_financial_audit.pdf"
  },
  "response": {
    "status": 200,
    "bytes": 4582910,
    "duration_ms": 142
  },
  "security": {
    "risk_level": "medium",
    "flags": ["write_operation"]
  }
}
```

---

## 5-Minute Deployment Guide on Cloudflare Workers

### 1. Prerequisites
- A Cloudflare account with Workers, KV, and R2 enabled.
- Node.js and [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) installed (`npm install -g wrangler`).

### 2. Create Resources & Clone Repository
```bash
# Create KV Namespace for licenses & quotas
wrangler kv namespace create LICENSES_KV

# Create R2 Bucket for real-time audit logs
wrangler r2 bucket create s3gw-audit-logs
```

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
GATEWAY_HOST = "s3gw.yourdomain.com" # Your Cloudflare Worker domain binding
# DISABLE_DLP_KV_WRITES = "true" # Audit/SaaS Mode (disables DLP KV writes)

[[kv_namespaces]]
binding = "LICENSES_KV"
id = "YOUR_CLOUDFLARE_KV_NAMESPACE_ID"

[[r2_buckets]]
binding = "R2_GATEWAY"
bucket_name = "s3gw-audit-logs"
```

> [!TIP]
> **Audit-Only Mode (Save KV Costs & Avoid False Positives)**
> By setting `DISABLE_DLP_KV_WRITES = "true"`, the gateway enters **Audit-Only Mode**. It enforces Blocklists (IPs, Countries, User-Agents, ASNs, Ransomware Killswitch) but skips DLP Quota KV writes and ignores Allowlists. Perfect for a safe, low-cost baseline.

### 3. Deploy to Cloudflare Edge
```bash
wrangler deploy
```

### 4. Client License Configuration (KV Namespace)

In your `LICENSES_KV` namespace, create a new key where the **Key Name** is your client's logic access key (e.g., `DEMO_S3GW_KEY`), and the **Value** is a JSON configuration like this example:

```json
{
  "activated": true,
  "expires_at": "2030-12-31T23:59:59Z",
  "gateway": {
    "enabled": true,
    "access_key": "DEMO_S3GW_KEY",
    "secret_key": "YOUR_GATEWAY_SECRET_KEY"
  },
  "bucket": "my-target-bucket",
  "endpoint": "s3.eu-west-3.amazonaws.com",
  "region": "eu-west-3",
  "accessKey": "AKIAX_REAL_S3_ACCESS_KEY",
  "secretKey": "REAL_S3_SECRET_KEY_abc123",
  "forceVirtualHost": true,
  "forcePathStyle": false,
  "security_policy": {
    "allowed_countries": ["FR", "DE", "BE", "CH", "US"],
    "blocked_countries": ["RU", "CN", "KP", "IR"],
    "blocked_asns": [4134, 4837, 3462],
    "allowed_ips": [],
    "blocked_ips": ["185.220.101.5"],
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

Now, point any S3 tool (AWS CLI, Cyberduck, Veeam, Terraform) to `https://s3gw.yourdomain.com/my-target-bucket` using `DEMO_S3GW_KEY` as Access Key and its associated `secret_key`!

---

## The Bridge to tamper — Deep S3 Object Security & FIM

S3GW natively integrates with **[tamper](https://tamper.fr)**. Connect your S3GW audit buckets to tamper to unlock instant visual dashboards, real-time SOC alerts, and automated deep-object verification (FIM) across all your clouds.

---

## Contributing & Open-Source Community

We love open-source! If you find **S3GW** useful:
1. **Star this repository** to support our research in open-source cloud security.
2. **Fork & Build:** Feel free to create your own implementation or port the S3GW logic to your favorite language.
3. **Submit PRs:** Found a bug or want to add new DLP detection rules? Pull requests are warmly welcomed!

---

## License & Credits

Developed by **[SIENNA](https://sienna.dev)** (the team behind [tamper](https://tamper.fr)).

Released under the **[Business Source License 1.1 (BSL)](./LICENSE)**.
> **What does this mean for you?**
> S3GW is a free, open-source tool for **Developers, DevSecOps, and DevOps**. You are entirely free to use, run, and modify this code for your own internal infrastructure (`DIY` / `On-Prem`). However, you **cannot** take this code and offer it as a competing commercial SaaS or sell it as a commercial product.
> If you wish to use S3GW as part of a commercial product, please contact SIENNA for licensing options.

---
