"""
Session manager (Tier-1 B1) — named principals for multi-user authz testing.

Holds a cookie jar + auth headers per NAMED session (anon / userA / userB / admin),
so one request can be replayed AS different principals — the primitive that unlocks
IDOR / BOLA / privilege-escalation testing (the highest-frequency real-bounty class).

Lean + local + single-user. Persisted to data/sessions.json (gitignored). You set a
session from a cookie you already have (paste from the browser / a login flow), the
same way the DVWA dogfood threads PHPSESSID — no heavy login-recipe engine.
"""
import os
import json
import time

_PATH = os.path.join("data", "sessions.json")


def _load() -> dict:
    try:
        with open(_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"sessions": {}}


def _save(d: dict) -> None:
    os.makedirs("data", exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)


def set_session(name: str, cookie: str = "", headers: dict = None,
                role: str = "user", note: str = "") -> dict:
    """Register/replace a principal. cookie = 'PHPSESSID=..; security=low' (browser/login
    capture); headers = {'Authorization': 'Bearer ..'} for token auth. role labels the
    principal (anon/user/admin) for authz reasoning."""
    name = (name or "").strip()
    if not name:
        return {}
    d = _load()
    d["sessions"][name] = {
        "cookie": cookie or "", "headers": dict(headers or {}),
        "role": role or "user", "note": note or "",
        "added": time.strftime("%Y-%m-%d %H:%M"),
    }
    _save(d)
    return d["sessions"][name]


def get(name: str) -> dict:
    return _load()["sessions"].get((name or "").strip())


def headers_for(name: str) -> dict:
    """Headers to send a request AS this principal (Cookie + any auth headers). None if unknown."""
    s = get(name)
    if s is None:
        return None
    h = dict(s.get("headers") or {})
    if s.get("cookie"):
        h["Cookie"] = s["cookie"]
    return h


def list_sessions() -> dict:
    return _load()["sessions"]


def delete(name: str) -> bool:
    d = _load()
    if (name or "").strip() in d["sessions"]:
        d["sessions"].pop(name.strip())
        _save(d)
        return True
    return False


def clear() -> None:                       # tests
    _save({"sessions": {}})
