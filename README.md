# mlab.sh Shuffle app

[Shuffle](https://shuffler.io) app for [**mlab.sh**](https://mlab.sh): core scanning, CVE intelligence and threat-actor data in your Shuffle workflows. Same surface as [`@mlabsh/n8n-nodes-mlab`](https://www.npmjs.com/package/@mlabsh/n8n-nodes-mlab).

| Group | Service | Auth |
|-------|---------|------|
| Domain / IP / Crypto / Hash / File / URL / Email / Phone / MAC / IOC / Quota | `mlab.sh/api/v1` | API key |
| CVE | `vuln.mlab.sh/api/v1` | none (public) |
| Threat actor | `actors.mlab.sh/api/v1` | none (public) |

## Installation

**From GitHub (Shuffle UI):** *Apps → Create / Import → Download from GitHub*, paste this repository URL. Shuffle builds `mlab/1.0.0`.

**Self-hosted, manually:** copy `mlab/` into your `shuffle-apps` folder (the `SHUFFLE_APP_HOTLOAD_FOLDER`) and hit *Reload apps* in the UI.

## Authentication

1. Create an API key at **mlab.sh → Account → Settings → API Keys** (starts with `mlab_`).
2. In Shuffle, authenticate the **mlab** app with it. It is sent as `Authorization: token mlab_...`.
3. `url` defaults to `https://mlab.sh/api/v1`; only change it for self-hosted instances.

Shuffle authenticates per app, so the key is also attached to the CVE / threat-actor actions; they simply ignore it.

## Actions

| Action | Endpoint | Notes |
|--------|----------|-------|
| `scan_domain` | `POST /scan/domain` | With `wait_for_completion=true` (default) polls status and returns `/scan/domain/results`. `timeout` in seconds (default 120). |
| `get_domain_status` / `get_domain_results` | `GET /scan/domain/status` / `results` | For scans you poll yourself. |
| `get_domain_ssl` | `GET /domain/ssl` | SSL certificates seen for the domain. |
| `capture_network_requests` | `GET /scan/domain/loadnetworkrequest` | Loads a page, returns every request it makes. |
| `lookup_ip` | `GET /scan/ip` | Geolocation, ASN, ownership. |
| `lookup_crypto` | `GET /scan/crypto` | Sanctions, labels, risk. `chain` blank = auto-detect. |
| `bulk_lookup_crypto` | `POST /scan/crypto` | List of addresses (comma / space / newline), batches of 100. |
| `lookup_hash` | `GET /scan/hash` | MD5 / SHA-1 / SHA-256 / SHA-512 verdict. |
| `bulk_lookup_hash` | `POST /scan/hash` | List of hashes, batches of 500. |
| `upload_file` | `POST /upload/file` | Takes a Shuffle `file_id` (max 10 MB), returns `sha256`. |
| `get_file_results` | `GET /scan/file/results` | By SHA-256. |
| `get_file_tool_output` | `GET /scan/file/output` | Raw output of one tool (e.g. `yara`). |
| `analyze_url` | `GET /scan/url` | `resolve=true` unmasks short links. |
| `analyze_email` | `GET /scan/email` | Mailbox type, spoofability, risk. |
| `analyze_phone` | `GET /scan/phone` | E.164 number. |
| `lookup_mac` | `GET /scan/mac` | Vendor, randomization, virtualization. |
| `extract_iocs` | `POST /scan/ioc` | Indicators from raw text. `risk=fast\|deep` adds SMS threat scoring, `country` picks the keyword pack. |
| `get_quota` | `GET /limit/{type}` | Remaining daily quota (domain / ip / file / crypto). |
| `search_cves` | `GET /cve?q=…` | Filters: `severity`, `published_after`, `exact`, `kev_only`. |
| `get_cve` | `GET /cve/{id}` | Includes EPSS and KEV. |
| `get_latest_cves` | `GET /cve/latest` | Last 7 days. |
| `list_threat_actors` | `GET /actors` | Filters: `origin`, `motivation`, `sector`; `limit` / `offset`. |
| `get_threat_actor` | `GET /actors/{slug}` | Aliases, tools, CVEs, techniques. |
| `get_actors_by_cve` | `GET /cves/{id}/actors` | Who exploits a given CVE. |

Actions return the raw mlab.sh JSON. On an HTTP error they return `{"success": false, "status": <code>, "error": <body>}`.

## Examples

- **Alert enrichment:** Webhook → `lookup_ip` / `analyze_url` on the alert's observables → attach to your case.
- **Vulnerability watch:** Schedule → `get_latest_cves` → filter `severity == CRITICAL` → notify.
- **Threat context:** `get_actors_by_cve` with `CVE-2021-44228` → add the actors to the incident.
- **Phishing triage:** email body → `extract_iocs` → `bulk_lookup_hash` / `analyze_url` on what it found.

## Development

```bash
pip install requests pyyaml && python tests/test_app.py
```

The test checks that `api.yaml` matches the Python signatures and that bulk lookups batch correctly.

## License

[MIT](LICENSE) · Threat-actor data is sourced from ETDA under CC BY-NC-SA 4.0.
