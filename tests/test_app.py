"""Run: python tests/test_app.py (needs requests + pyyaml). Stubs the Shuffle SDK."""
import inspect
import os
import sys
import types

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..", "mlab", "1.1.0")
sdk = types.ModuleType("shuffle_sdk")
sdk.AppBase = type("AppBase", (), {"__init__": lambda self, *a, **k: None})
sys.modules["shuffle_sdk"] = sdk
sys.path.insert(0, os.path.join(ROOT, "src"))
import app  # noqa: E402

# api.yaml actions must match the Python signatures (Shuffle passes auth params to every action).
spec = yaml.safe_load(open(os.path.join(ROOT, "api.yaml")))
auth = [p["name"] for p in spec["authentication"]["parameters"]]
for action in spec["actions"]:
    fn = getattr(app.Mlab, action["name"])
    args = set(inspect.signature(fn).parameters) - {"self"}
    declared = set(auth) | {p["name"] for p in action.get("parameters", [])}
    assert args == declared, (action["name"], args ^ declared)

assert app.split_list("a, b\nb;c  ") == ["a", "b", "c"]

# Bulk hash lookups batch by 500.
calls = []
m = app.Mlab(None, None)
m._core = lambda apikey, url, method, path, json=None, **k: calls.append(json) or {"n": len(json["hashes"])}
res = m.bulk_lookup_hash("k", " ".join("h%d" % i for i in range(1201)))
assert [r["n"] for r in res] == [500, 500, 201], res
assert m.bulk_lookup_hash("k", "x") == {"n": 1}

# Error handling: clear 401 / 429 messages, quota headers surfaced.
class Resp:
    def __init__(self, status, body, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.ok = status < 400
        self.text = str(body)

    def json(self):
        return self._body

r = app.respond(Resp(401, {"error": "Unauthorized"}))
assert r["success"] is False and r["status"] == 401 and "expire" in r["message"], r
r = app.respond(Resp(429, {"error": "limit"}, {"Retry-After": "3600", "X-RateLimit-Remaining": "0"}))
assert r["retry_after"] == 3600 and r["rate_limit"]["remaining"] == 0 and "429" in r["message"], r
r = app.respond(Resp(200, {"ip": "8.8.8.8"}, {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "41",
                                             "X-RateLimit-Resource": "ip", "X-RateLimit-Window": "86400"}))
assert r["rate_limit"] == {"limit": 100, "remaining": 41, "resource": "ip", "window_seconds": 86400}, r
assert app.respond(Resp(200, [1, 2])) == [1, 2], "list bodies are left alone"
assert "rate_limit" not in app.respond(Resp(200, {"a": 1}))

# Domain scan: waits on status, then the v2 report by default, v1 on request; failed report is an error.
def fake(report_status="completed"):
    seen = []

    def core(apikey, url, method, path, params=None, json=None, **k):
        seen.append(path)
        if path == "/scan/domain/status":
            return {"status": "success"}
        if path == "/scan/domain/report":
            return {"schema": "domain-report/2", "status": report_status}
        return {"ok": True}
    m = app.Mlab(None, None)
    m._core = core
    return m, seen

m, seen = fake()
assert m.scan_domain("k", "x.com")["schema"] == "domain-report/2" and seen[-1] == "/scan/domain/report"
m, seen = fake()
m.scan_domain("k", "x.com", output="results")
assert seen[-1] == "/scan/domain/results", seen
m, seen = fake("failed")
assert m.scan_domain("k", "x.com")["success"] is False
m, seen = fake()
m.scan_domain("k", "x.com", wait_for_completion="false")
assert seen == ["/scan/domain"], seen

# Bodies of the SOAR actions match the API handlers.
sent = []
m = app.Mlab(None, None)
m._core = lambda apikey, url, method, path, params=None, json=None, **k: sent.append((method, path, params, json)) or {"uuid": "c1"}
m.create_case("k", "T", indicators="8.8.8.8")
assert sent[-2][1:] == ("/cases/create", None, {"title": "T", "summary": ""})
assert sent[-1][1:] == ("/cases/indicator/add", None, {"uuid": "c1", "indicators": "8.8.8.8"})
m.update_case("k", "c1", status="closed")
assert sent[-1][3] == {"uuid": "c1", "status": "closed"}
m.add_case_comment("k", "c1", "hi")
assert sent[-1][3] == {"uuid": "c1", "body": "hi"}
m.create_watchdog("k", "x.com", "monthly", day_of_month="3")
assert sent[-1][3] == {"domain": "x.com", "frequency": "monthly", "scan_type": "domain", "hour": 9, "minute": 0, "day_of_month": 3}
m.update_watchdog("k", "w1", "false")
assert sent[-1][3] == {"uuid": "w1", "enabled": False}
m.add_finding_tag("k", "s1", "f1", "fixed")
assert sent[-1][1:3] == ("/scan/finding-tags/add", {"scan_uuid": "s1", "finding_id": "f1", "tag": "fixed"})
m.triage_batch("k", "a\nb")
assert sent[-1][1:] == ("/scan/batch", None, {"indicators": "a\nb"})
print("ok")
