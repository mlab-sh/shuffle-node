import re
import time

import requests
from shuffle_sdk import AppBase

CVE_BASE_URL = "https://vuln.mlab.sh/api/v1"
ACTORS_BASE_URL = "https://actors.mlab.sh/api/v1"
DEFAULT_URL = "https://mlab.sh/api/v1"


def split_list(raw):
    """Split a pasted list on commas, whitespace or new lines, dropping blanks and duplicates."""
    return list(dict.fromkeys(v for v in re.split(r"[\s,;]+", raw or "") if v))


def is_true(value):
    return str(value).strip().lower() in ("true", "1", "yes")


RATE_HEADERS = {
    "X-RateLimit-Limit": "limit",
    "X-RateLimit-Remaining": "remaining",
    "X-RateLimit-Resource": "resource",
    "X-RateLimit-Window": "window_seconds",
}


def rate_limit(headers):
    """The quota headers mlab.sh sends on key calls that spend quota, or None."""
    out = {v: headers[k] for k, v in RATE_HEADERS.items() if k in headers}
    for k in ("limit", "remaining", "window_seconds"):
        if str(out.get(k, "")).isdigit():
            out[k] = int(out[k])
    return out or None


def error_message(status, body, headers):
    if status == 401:
        return ("mlab.sh refused the API key (401): it is unknown, revoked or expired. Keys expire after "
                "90 days by default; create a new one in Organization settings → API keys and re-authenticate the app.")
    if status == 403:
        detail = body.get("error") if isinstance(body, dict) else body
        return "mlab.sh refused the call (403): %s" % (detail or "this API key lacks the permission for this action.")
    if status == 429:
        return ("mlab.sh quota spent for this resource (429). Retry after %ss or raise the plan's quota."
                % headers.get("Retry-After", "3600"))
    return None


def respond(r):
    try:
        body = r.json()
    except ValueError:
        body = r.text
    limits = rate_limit(r.headers)
    if r.ok:
        if limits and isinstance(body, dict):
            body.setdefault("rate_limit", limits)
        return body
    out = {"success": False, "status": r.status_code, "error": body}
    message = error_message(r.status_code, body, r.headers)
    if message:
        out["message"] = message
    if r.status_code == 429:
        out["retry_after"] = int(r.headers.get("Retry-After", "3600"))
    if limits:
        out["rate_limit"] = limits
    return out


def failed(result):
    return isinstance(result, dict) and result.get("success") is False


class Mlab(AppBase):
    __version__ = "1.1.0"
    app_name = "mlab"

    def __init__(self, redis, logger, console_logger=None):
        super().__init__(redis, logger, console_logger)

    # --- HTTP helpers --------------------------------------------------------

    def _core(self, apikey, url, method, path, params=None, json=None, files=None):
        base = (url or DEFAULT_URL).rstrip("/")
        # The upload endpoint lives at the site root, not under /api/v1.
        if path.startswith("/upload/"):
            base = re.sub(r"/api/v1$", "", base)
        r = requests.request(
            method,
            base + path,
            params=params,
            json=json,
            files=files,
            headers={"Authorization": "token " + apikey},
            timeout=120,
        )
        return respond(r)

    def _public(self, base, path, params=None):
        return respond(requests.get(base + path, params=params, timeout=60))

    # --- Domain ---------------------------------------------------------------

    def scan_domain(self, apikey, domain, wait_for_completion="true", timeout="120", output="report", url=DEFAULT_URL):
        """Launch a scan; when waiting, return the v2 report (default) or the legacy v1 results."""
        launch = self._core(apikey, url, "POST", "/scan/domain", json={"domain": domain})
        if not is_true(wait_for_completion) or failed(launch):
            return launch
        path = "/scan/domain/results" if output == "results" else "/scan/domain/report"

        deadline = time.time() + int(timeout or 120)
        while time.time() < deadline:
            status = self._core(apikey, url, "GET", "/scan/domain/status", params={"domain": domain})
            state = status.get("status", status.get("state")) if isinstance(status, dict) else None
            if state == "success":
                result = self._core(apikey, url, "GET", path, params={"domain": domain})
                if path.endswith("/report") and isinstance(result, dict) and result.get("status") == "failed":
                    return {"success": False, "error": 'Domain scan failed for "%s"' % domain, "report": result}
                return result
            if state == "error" or state is False:
                return {"success": False, "error": 'Domain scan failed for "%s"' % domain, "status": status}
            time.sleep(4)
        return {
            "success": False,
            "error": 'Domain scan for "%s" did not finish within %ss. Use get_domain_results later.' % (domain, timeout),
        }

    def get_domain_status(self, apikey, domain, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/domain/status", params={"domain": domain})

    def get_domain_report(self, apikey, domain, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/domain/report", params={"domain": domain})

    def get_domain_results(self, apikey, domain, url=DEFAULT_URL):
        """Legacy v1 payload, frozen upstream. Prefer get_domain_report."""
        return self._core(apikey, url, "GET", "/scan/domain/results", params={"domain": domain})

    def get_domain_ssl(self, apikey, domain, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/domain/ssl", params={"domain": domain})

    def capture_network_requests(self, apikey, page_url, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/domain/loadnetworkrequest", params={"url": page_url})

    # --- IP / crypto / hash ---------------------------------------------------

    def lookup_ip(self, apikey, ip, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/ip", params={"ip": ip})

    def lookup_crypto(self, apikey, address, chain="", url=DEFAULT_URL):
        params = {"address": address}
        if chain:
            params["chain"] = chain
        return self._core(apikey, url, "GET", "/scan/crypto", params=params)

    def bulk_lookup_crypto(self, apikey, addresses, chain="", url=DEFAULT_URL):
        return self._bulk(apikey, url, "/scan/crypto", "addresses", split_list(addresses), 100, chain)

    def lookup_hash(self, apikey, hash, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/hash", params={"hash": hash})

    def bulk_lookup_hash(self, apikey, hashes, url=DEFAULT_URL):
        return self._bulk(apikey, url, "/scan/hash", "hashes", split_list(hashes), 500)

    def _bulk(self, apikey, url, path, field, values, size, chain=""):
        """Send values in as few requests as the API allows; one response per batch."""
        out = []
        for start in range(0, len(values), size):
            body = {field: values[start:start + size]}
            if chain:
                body["chain"] = chain
            out.append(self._core(apikey, url, "POST", path, json=body))
        return out[0] if len(out) == 1 else out

    # --- File -----------------------------------------------------------------

    def upload_file(self, apikey, file_id, url=DEFAULT_URL):
        f = self.get_file(file_id)
        files = {"file": (f.get("filename") or "file", f["data"])}
        return self._core(apikey, url, "POST", "/upload/file", files=files)

    def get_file_results(self, apikey, sha256, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/file/results", params={"sha256": sha256})

    def get_file_tool_output(self, apikey, sha256, tool, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/file/output", params={"sha256": sha256, "tool": tool})

    # --- URL / email / phone / MAC / IOC ----------------------------------------

    def analyze_url(self, apikey, target_url, resolve="false", url=DEFAULT_URL):
        params = {"url": target_url}
        if is_true(resolve):
            params["resolve"] = "true"
        return self._core(apikey, url, "GET", "/scan/url", params=params)

    def analyze_email(self, apikey, email, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/email", params={"email": email})

    def analyze_phone(self, apikey, number, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/phone", params={"number": number})

    def lookup_mac(self, apikey, mac, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/mac", params={"mac": mac})

    def extract_iocs(self, apikey, text, risk="", country="", url=DEFAULT_URL):
        params = {}
        if risk:
            params["risk"] = risk
            if country:
                params["country"] = country
        return self._core(apikey, url, "POST", "/scan/ioc", params=params, json={"text": text})

    def get_quota(self, apikey, scan_type="domain", url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/limit/" + scan_type)

    def triage_batch(self, apikey, indicators, url=DEFAULT_URL):
        """Type, de-duplicate and enrich a paste from mlab.sh's caches. Spends no lookup."""
        return self._core(apikey, url, "POST", "/scan/batch", json={"indicators": indicators})

    # --- Cases (Team plan) -------------------------------------------------------

    def list_cases(self, apikey, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/cases")

    def get_case(self, apikey, case_uuid, url=DEFAULT_URL):
        return self._core(apikey, url, "POST", "/cases/detail", json={"uuid": case_uuid})

    def create_case(self, apikey, title, summary="", indicators="", url=DEFAULT_URL):
        created = self._core(apikey, url, "POST", "/cases/create", json={"title": title, "summary": summary})
        if indicators.strip() and isinstance(created, dict) and created.get("uuid"):
            created["indicators"] = self.add_case_indicators(apikey, created["uuid"], indicators, url)
        return created

    def update_case(self, apikey, case_uuid, title="", summary="", status="", url=DEFAULT_URL):
        body = {"uuid": case_uuid}
        if title:
            body["title"] = title
        if summary:
            body["summary"] = summary
        if status:
            body["status"] = status
        return self._core(apikey, url, "POST", "/cases/update", json=body)

    def add_case_indicators(self, apikey, case_uuid, indicators, url=DEFAULT_URL):
        return self._core(apikey, url, "POST", "/cases/indicator/add", json={"uuid": case_uuid, "indicators": indicators})

    def add_case_comment(self, apikey, case_uuid, comment, indicator_uuid="", url=DEFAULT_URL):
        body = {"uuid": case_uuid, "body": comment}
        if indicator_uuid:
            body["indicator_uuid"] = indicator_uuid
        return self._core(apikey, url, "POST", "/cases/comment/add", json=body)

    # --- Watchdog (scheduled scans) ------------------------------------------------

    def list_watchdogs(self, apikey, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/watchdog/list")

    def create_watchdog(self, apikey, target, frequency="weekly", scan_type="domain", hour="9", minute="0",
                        day_of_week="", day_of_month="", url=DEFAULT_URL):
        body = {"domain": target, "frequency": frequency, "scan_type": scan_type,
                "hour": int(hour or 9), "minute": int(minute or 0)}
        if str(day_of_week).strip():
            body["day_of_week"] = int(day_of_week)
        if str(day_of_month).strip():
            body["day_of_month"] = int(day_of_month)
        return self._core(apikey, url, "POST", "/scan/watchdog/create", json=body)

    def update_watchdog(self, apikey, watchdog_uuid, enabled, url=DEFAULT_URL):
        return self._core(apikey, url, "POST", "/scan/watchdog/update",
                          json={"uuid": watchdog_uuid, "enabled": is_true(enabled)})

    def delete_watchdog(self, apikey, watchdog_uuid, url=DEFAULT_URL):
        return self._core(apikey, url, "POST", "/scan/watchdog/delete", json={"uuid": watchdog_uuid})

    # --- Finding tags (RedKit triage) -------------------------------------------------

    def list_finding_tags(self, apikey, scan_uuid, url=DEFAULT_URL):
        return self._core(apikey, url, "GET", "/scan/finding-tags", params={"scan_uuid": scan_uuid})

    def add_finding_tag(self, apikey, scan_uuid, finding_id, tag, url=DEFAULT_URL):
        params = {"scan_uuid": scan_uuid, "finding_id": finding_id, "tag": tag}
        return self._core(apikey, url, "POST", "/scan/finding-tags/add", params=params, json={})

    def remove_finding_tag(self, apikey, scan_uuid, finding_id, tag, url=DEFAULT_URL):
        params = {"scan_uuid": scan_uuid, "finding_id": finding_id, "tag": tag}
        return self._core(apikey, url, "POST", "/scan/finding-tags/remove", params=params, json={})

    # --- CVE (public) ---------------------------------------------------------

    def search_cves(self, apikey, query, severity="", published_after="", exact="false", kev_only="false", url=DEFAULT_URL):
        params = {"q": query}
        if severity:
            params["severity"] = severity
        if published_after:
            params["dateStart"] = published_after[:10]
        if is_true(exact):
            params["exact"] = 1
        if is_true(kev_only):
            params["kev"] = 1
        return self._public(CVE_BASE_URL, "/cve", params)

    def get_cve(self, apikey, cve_id, url=DEFAULT_URL):
        return self._public(CVE_BASE_URL, "/cve/" + requests.utils.quote(cve_id.strip().upper()))

    def get_latest_cves(self, apikey, url=DEFAULT_URL):
        return self._public(CVE_BASE_URL, "/cve/latest")

    # --- Threat actors (public) ---------------------------------------------------

    def list_threat_actors(self, apikey, origin="", motivation="", sector="", limit="50", offset="0", url=DEFAULT_URL):
        params = {"limit": limit or 50, "offset": offset or 0}
        for k, v in (("origin", origin), ("motivation", motivation), ("sector", sector)):
            if v:
                params[k] = v
        return self._public(ACTORS_BASE_URL, "/actors", params)

    def get_threat_actor(self, apikey, slug, url=DEFAULT_URL):
        return self._public(ACTORS_BASE_URL, "/actors/" + requests.utils.quote(slug.strip()))

    def get_actors_by_cve(self, apikey, cve_id, url=DEFAULT_URL):
        return self._public(ACTORS_BASE_URL, "/cves/%s/actors" % requests.utils.quote(cve_id.strip().upper()))


if __name__ == "__main__":
    Mlab.run()
