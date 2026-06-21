"""
Phase 36 — HackingTool wrapper (scoped) for Ultron.

Wraps the bundled hackingtool index (183 tools) + ht_run.py backend runner
(native / WSL / Docker auto-select) behind Ultron's security model.

Hard gates enforced here — NOT in ht_run.py:
  1. Allowlist — only SAFE_TOOLS reachable from the router. Offensive categories
     (ddos, phishing payloads, wifi-jam, post-exploitation C2, payload creators,
     android attack, remote admin shells) are NEVER runnable through this wrapper.
  2. No --command / --force / --privileged ever passed (no arbitrary shell).
  3. Primary defense (W1 fix): ht_run.py execs argv via shlex.split with NO shell
     (`bash -lc` removed), so shell metacharacters can't inject commands. The
     metachar reject below is kept as defense-in-depth.
  4. Backend forced from config (default "auto"; "docker" for isolation).

Source: github.com/AKCodez/hackingtool-plugin (wraps Z4nzu/hackingtool).
"""

import os
import re
import json
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(_HERE, "scripts")
_TOOLS_JSON = os.path.join(_HERE, "data", "tools.json")

# Backend: "auto" (ht_env picks WSL>Docker on Windows), "docker", "wsl", "native"
try:
    from config import HT_BACKEND  # type: ignore
except Exception:
    HT_BACKEND = os.environ.get("HT_BACKEND", "auto")

# Defense-in-depth: reject shell-injection chars. (Primary defense is now argv-exec
# in ht_run.py — no shell — but we still drop obviously-hostile args at the gate.)
_SHELL_META = re.compile(r"[;&|`$<>\n\r\\(){}]")

# ── Allowlist: SAFE recon / OSINT / discovery / audit (router-exposed) ──────────
SAFE_TOOLS = {
    # passive recon / OSINT
    "information_gathering.Amass",
    "information_gathering.Subfinder",
    "information_gathering.Httpx",
    "information_gathering.TheHarvester",
    "information_gathering.Holehe",
    "information_gathering.Maigret",
    "information_gathering.SpiderFoot",
    "information_gathering.TruffleHog",
    "information_gathering.Gitleaks",
    "information_gathering.RedHawk",
    "information_gathering.Infoga",
    # web — non-destructive probes
    "web_attack.Nuclei",
    "web_attack.Wafw00f",
    "web_attack.CheckURL",
    "web_attack.TestSSL",
    "web_attack.Katana",
    "web_attack.Arjun",
    # typosquat / brand OSINT (defensive)
    "phishing_attack.Dnstwist",
    # cloud posture audit (read-only)
    "cloud_security.Prowler",
    "cloud_security.ScoutSuite",
    # forensics (local file analysis)
    "forensics.Binwalk",
}

# ── EXTENDED: active web tools (fuzzing/active scan). Gated — needs explicit allow.
EXTENDED_TOOLS = {
    "web_attack.Ffuf",
    "web_attack.Gobuster",
    "web_attack.Dirsearch",
    "xss_attack.XSpear",
}

ALLOWED = SAFE_TOOLS | EXTENDED_TOOLS


def _load_index() -> dict:
    with open(_TOOLS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


# case-insensitive: router lowercases input, but index ids are CamelCased
_CANON = {tid.lower(): tid for tid in ALLOWED}


def _canon(tool_id: str) -> str:
    """Resolve a (possibly lowercased) id to its canonical allowlisted form."""
    tid = (tool_id or "").strip()
    return _CANON.get(tid.lower(), tid)


def _find(tool_id: str) -> dict | None:
    for t in _load_index()["tools"]:
        if t["id"] == tool_id:
            return t
    return None


def ht_preflight() -> dict:
    """Detect execution backend (native/WSL/Docker). Returns env dict + verdict."""
    try:
        r = subprocess.run(
            ["python", os.path.join(_SCRIPTS, "ht_env.py")],
            capture_output=True, text=True, timeout=20, cwd=_SCRIPTS,
        )
        env = json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception as e:
        return {"ready": False, "message": f"preflight failed: {e}", "env": {}}

    backend = env.get("preferred_backend", "fallback")
    ready = backend != "fallback"
    msg = (
        f"Backend: {backend} (host={env.get('host')}, docker={env.get('docker')}, "
        f"wsl={env.get('wsl_distros')})"
        if ready else
        "No Linux runtime. Install WSL (`wsl --install -d Ubuntu`) or start Docker Desktop."
    )
    return {"ready": ready, "backend": backend, "message": msg, "env": env}


def ht_search(query: str = "", category: str = "", limit: int = 15) -> dict:
    """Search the tool index. Marks which results are allowlisted/runnable."""
    q = (query or "").lower().strip()
    cat = (category or "").lower().strip()
    out = []
    for t in _load_index()["tools"]:
        hay = f"{t['id']} {t['title']} {t['description']}".lower()
        if q and q not in hay:
            continue
        if cat and cat != t["category"].lower():
            continue
        tier = ("safe" if t["id"] in SAFE_TOOLS
                else "extended" if t["id"] in EXTENDED_TOOLS
                else "blocked")
        out.append({
            "id": t["id"],
            "title": t["title"],
            "category": t["category"],
            "tier": tier,
            "runnable": t["id"] in ALLOWED,
        })
        if len(out) >= limit:
            break
    return {"count": len(out), "results": out}


def ht_run(tool_id: str, args: str = "", allow_extended: bool = False,
           timeout: int = 180) -> dict:
    """
    Run an allowlisted tool via ht_run.py. Returns the runner's JSON dict.

    Gates: tool_id must be in SAFE_TOOLS (or EXTENDED_TOOLS when allow_extended).
    Args are sanitized; --command/--force/--privileged are never used.
    """
    tool_id = _canon(tool_id)
    if tool_id not in ALLOWED:
        return {"status": "refused",
                "message": f"'{tool_id}' is not in Ultron's allowlist. "
                           f"Use ht_search to find safe tool ids."}
    if tool_id in EXTENDED_TOOLS and not allow_extended:
        return {"status": "refused",
                "message": f"'{tool_id}' is an active scanner (extended tier). "
                           f"Pass allow_extended=True to run it on an authorized target."}

    args = args or ""
    if _SHELL_META.search(args):
        return {"status": "refused",
                "message": f"refused args with shell metacharacters: {args!r}"}

    if not _find(tool_id):
        return {"status": "error", "message": f"tool not in index: {tool_id}"}

    cmd = ["python", os.path.join(_SCRIPTS, "ht_run.py"), tool_id,
           "--backend", HT_BACKEND, "--timeout", str(timeout)]
    if args:
        cmd += ["--args", args]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout + 30, cwd=_SCRIPTS)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "message": f"runner timed out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "message": f"runner error: {e}"}

    try:
        return json.loads(r.stdout)
    except Exception:
        return {"status": "error", "message": "could not parse runner output",
                "stdout": (r.stdout or "")[:2000], "stderr": (r.stderr or "")[:1000]}
