"""Run: python tests/test_app.py (needs requests + pyyaml). Stubs the Shuffle SDK."""
import inspect
import os
import sys
import types

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..", "mlab", "1.0.0")
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
print("ok")
