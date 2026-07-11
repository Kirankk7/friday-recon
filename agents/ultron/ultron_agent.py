import os
import re
import json
import platform
import subprocess
import datetime
import psutil
import socket

from core.llm import ask_llm
from core.throttle import throttle
from core.critic import refine as _critic_refine
from agents.ultron import report, gate   # Phase B: report/analysis cluster + validation gate
from agents.ultron import evidence as evidence_bundle   # Phase B: F3 evidence-bundle writer
from agents.ultron import cve as cve_lookup   # Phase B: CVE lookup / NVD cluster
from agents.ultron.cve import cve_product_keywords as _cve_product_keywords, match_products as _match_products
from agents.ultron import knowledge   # Phase B: playbook recall / remember-technique

_CVE_FILE = "data/cve_watchlist.json"

try:
    import nmap
    NMAP_LIB = True
except ImportError:
    NMAP_LIB = False


import os as _os

# Absolute paths for tools — bypass PATH issues
_GOBIN    = _os.path.join(_os.path.expanduser("~"), "go", "bin")
_NMAP_EXE = r"C:\Program Files (x86)\Nmap\nmap.exe"

_ENV = _os.environ.copy()
_ENV["PATH"] = _GOBIN + ";" + r"C:\Program Files (x86)\Nmap" + ";" + _ENV.get("PATH", "")


def _resolve(tool: str) -> str:
    """Return absolute path for known tools, else tool name for PATH lookup."""
    known = {
        "nmap":      _NMAP_EXE,
        "subfinder": _os.path.join(_GOBIN, "subfinder.exe"),
        "httpx":     _os.path.join(_GOBIN, "httpx.exe"),
        "nuclei":    _os.path.join(_GOBIN, "nuclei.exe"),
        "katana":    _os.path.join(_GOBIN, "katana.exe"),
        "ffuf":      _os.path.join(_GOBIN, "ffuf.exe"),
        "gobuster":  _os.path.join(_GOBIN, "gobuster.exe"),
    }
    resolved = known.get(tool, tool)
    # Fallback to plain name if resolved path doesn't exist
    if not _os.path.exists(resolved):
        return tool
    return resolved


def tool_exists(name: str) -> bool:
    """Check if tool is available."""
    try:
        subprocess.run(
            [_resolve(name), "--version"],
            capture_output=True,
            timeout=5,
            env=_ENV
        )
        return True
    except Exception:
        return False


# Phase 40c — shell execution hardening (adapted from OpenJarvis)
# Only these binaries may be invoked. Anything else is refused.
_TOOL_ALLOWLIST = {
    "nmap", "subfinder", "httpx", "nuclei", "katana",
    "ffuf", "gobuster", "feroxbuster",   # content discovery (recon-only)
}
# Shell metacharacters that should never appear in a tool argument.
# We run with list-form subprocess (no shell), but reject these as defense-in-depth.
import re as _re_guard
_SHELL_META = _re_guard.compile(r"[;&|`$<>\n\r\\]")


def _sanitize_arg(arg: str) -> str:
    """Reject args containing shell metacharacters (command-injection chars)."""
    if not isinstance(arg, str):
        arg = str(arg)
    if _SHELL_META.search(arg):
        raise ValueError(f"refused argument with shell metacharacters: {arg!r}")
    return arg


def run_cmd(cmd: list, timeout: int = 60) -> str:
    """Run an allowlisted CLI tool, return stdout+stderr. List-form (no shell)."""
    if not cmd:
        return "Error: empty command."

    tool = cmd[0]
    if tool not in _TOOL_ALLOWLIST:
        return f"Refused: '{tool}' is not an allowlisted security tool."

    # Sanitize every argument (flags + targets) for injection chars
    try:
        safe_args = [_sanitize_arg(a) for a in cmd[1:]]
    except ValueError as e:
        return f"Refused: {e}"

    resolved_cmd = [_resolve(tool)] + safe_args
    try:
        result = subprocess.run(
            resolved_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_ENV,
            shell=False,   # explicit — never invoke via shell
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "Timed out."
    except FileNotFoundError:
        return f"Tool not found: {tool}"
    except Exception as e:
        return f"Error: {str(e)}"


def _parse_nmap_voice(raw: str, target: str) -> str:
    """Convert raw nmap output to short voice-friendly summary."""
    lines = raw.splitlines()
    open_ports = []
    for line in lines:
        # Match lines like: 22/tcp   open  ssh
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "open":
                open_ports.append(f"{parts[2]} ({parts[0]})")
    if not open_ports:
        if "filtered" in raw.lower():
            return (f"Nmap: all scanned ports on {target} are filtered (firewall / cloud "
                    f"security-group dropping probes) — host may still serve HTTP; httpx confirms.")
        return f"Nmap found no open ports on {target}."
    ports_str = ", ".join(open_ports[:10])
    suffix = f" and {len(open_ports)-10} more" if len(open_ports) > 10 else ""
    return f"Nmap found {len(open_ports)} open port{'s' if len(open_ports)!=1 else ''} on {target}: {ports_str}{suffix}."


def _ipv4_local(target: str) -> str:
    """Pin localhost -> 127.0.0.1. Go tools (httpx/nuclei/katana) resolve localhost
    to IPv6 ::1, but local dev servers often bind IPv4 only, so they silently get
    nothing. Real domains are untouched."""
    return re.sub(r"(^|//)(localhost)(?=[:/]|$)", r"\g<1>127.0.0.1", target or "")


def _resolve_scheme(target: str) -> str:
    """Pick a scheme that actually responds for a bare host.

    Bug-bounty/recon used to hardcode https:// — http-only targets (e.g. many
    test/legacy hosts on port 80) then silently returned nothing, and the LLM
    rationalised the empty result as 'low risk'. This probes https then http and
    returns the first that answers (any HTTP status = reachable), defaulting to
    https. Already-schemed targets pass through untouched.
    """
    target = _ipv4_local(target)
    if target.startswith(("http://", "https://")):
        return target
    import urllib.request
    import urllib.error
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=6)
            return url
        except urllib.error.HTTPError:
            return url            # server answered (4xx/5xx) -> scheme is live
        except Exception:
            continue              # connection failed -> try next scheme
    return f"https://{target}"    # neither reachable -> default, pipeline flags inconclusive


_SCAN_HISTORY_FILE = "data/scan_history.json"


def _extract_open_ports(raw: str) -> list:
    """Pull 'port/proto service' tokens for open ports from nmap output."""
    ports = []
    for line in raw.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "open":
                svc = parts[2] if len(parts) >= 3 else ""
                ports.append(f"{parts[0]} {svc}".strip())
    # dedupe, stable order
    seen = set()
    out = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _load_scan_history() -> dict:
    try:
        if os.path.exists(_SCAN_HISTORY_FILE):
            with open(_SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_scan_history(hist: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_SCAN_HISTORY_FILE), exist_ok=True)
        with open(_SCAN_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(hist, f, indent=2)
    except Exception as e:
        print(f"[ULTRON] scan history save error: {e}")


def _diff_scan(target: str, scan_type: str, raw: str) -> str:
    """Compare this scan's open ports to last scan of same target. Returns diff sentence or ''."""
    ports = _extract_open_ports(raw)
    hist = _load_scan_history()
    prev = hist.get(target, {}).get("ports")

    hist[target] = {
        "ports": ports,
        "scan_type": scan_type,
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    _save_scan_history(hist)

    if prev is None:
        return ""  # first scan of this target — nothing to diff

    prev_set, cur_set = set(prev), set(ports)
    added = sorted(cur_set - prev_set)
    removed = sorted(prev_set - cur_set)

    if not added and not removed:
        return "No change since last scan."

    bits = []
    if added:
        bits.append(f"{len(added)} newly open ({', '.join(added)})")
    if removed:
        bits.append(f"{len(removed)} now closed ({', '.join(removed)})")
    return "Change since last scan: " + "; ".join(bits) + "."


# _cve_product_keywords / _match_products moved to agents/ultron/cve.py (Phase B);
# imported back at module top so ultron_agent._cve_product_keywords still resolves.


def _service_tokens(services: list) -> set:
    """Service-name tokens from scan history port entries ('22/tcp ssh' -> {'ssh'})."""
    toks = set()
    for s in services:
        parts = s.split()  # "22/tcp ssh"
        for p in parts[1:]:  # skip port/proto
            p = p.strip().lower()
            if len(p) > 2:
                toks.add(p)
    return toks


# ── Bug-bounty workflow (Phase 54) ────────────────────────────────────────────
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


# Error-based SQLi response signatures (DB engine error strings leaking into the page).
_SQL_ERROR_SIGNS = re.compile(
    r"sql syntax|mysql_fetch|you have an error in your sql|ORA-\d{5}|"
    r"microsoft ole db|unclosed quotation mark|sqlite_error|sqlstate|"
    r"npgsql|psqlexception|pg::syntaxerror|syntax error at or near|"
    r"warning:\s*mysql|valid mysql result|sqlexception|incorrect syntax near|"
    r"odbc.*driver|microsoft jet database|"
    # sqlite (python DB-API) — these are DB-specific enough not to false-match generic 500s
    r"sqlite3\.\w*error|unrecognized token|no such (?:table|column)|sql logic error",
    re.IGNORECASE)
# Type / numeric-cast / input-validation error signatures. A quote that flips 200->500
# by breaking an int()/parseInt() cast is a VALIDATION error, NOT injection — the endpoint
# rejects any non-numeric input, not the quote specifically. Used to DROP injection-error-
# anomaly false-positives (DSVW `?size=` dogfood FP: int("32'") -> ValueError). Kept tight to
# numeric-cast failures so it never masks a real injection anomaly (file-open / SQL / XPath
# breaks do NOT match). Signature-based (not a differential re-test): a `1x` control probe
# would also 500 numeric SQLi (`id=1x` -> sqlite "unrecognized token"), false-dropping real bugs.
_TYPE_ERROR_SIGNS = re.compile(
    r"invalid literal for int|could not convert string to (?:float|int)|"
    r"invalid input syntax for (?:type )?(?:integer|numeric|bigint|double)|"
    r"numberformatexception|for input string:|"          # Java Integer.parseInt("32'")
    r"cannot convert.*? to (?:int|number|numeric)|is not a valid (?:integer|number)|"
    r"System\.FormatException",
    re.IGNORECASE)
# Unique-ish token for reflected-XSS detection (with angle brackets to prove no encoding).
_XSS_MARKER = "jvz9xqk7z"
# NoSQL injection error signatures (Mongo/Mongoose/CouchDB parse errors leaking into the page).
_NOSQL_ERROR_SIGNS = re.compile(
    r"mongoerror|mongoservererror|cast to objectid failed|"
    r"\$where|\$regex|bson|unexpected token.*in json|"
    r"casterror|e11000|couchdb|unknown operator|\$gt|\$ne",
    re.IGNORECASE)
# Host-header injection marker — reflected in a Location header / body = poisoning candidate.
_HHI_MARKER = "jvz9hhi.example"
# Command-injection oracle: marker halves wrap a shell ARITHMETIC expansion. If the shell
# runs it, the response shows jvz9c49jvz9c; a mere reflection shows the literal $((7*7)) —
# so the executed form can NOT be produced by reflection (kills the XSS-style FP).
_CMDI_MARK = "jvz9c"
_CMDI_HIT = re.compile(re.escape(_CMDI_MARK) + r"49" + re.escape(_CMDI_MARK))
_CMDI_PAYLOADS = (";echo " + _CMDI_MARK + "$((7*7))" + _CMDI_MARK + ";",
                  "|echo " + _CMDI_MARK + "$((7*7))" + _CMDI_MARK,
                  "$(echo " + _CMDI_MARK + "$((7*7))" + _CMDI_MARK + ")")
# SSTI oracle: a UNIQUE arithmetic (1337*1337=1787569, unlikely to occur in page text).
# If the template engine evals it the response shows 1787569; a reflection shows the literal
# expression. Covers Jinja2/Twig {{ }}, Freemarker/Velocity ${ }, Razor #{ }, Smarty { }.
_SSTI_PAYLOADS = ("{{1337*1337}}", "${1337*1337}", "#{1337*1337}", "{1337*1337}")
_SSTI_HIT = re.compile(r"1787569")
# Time-based blind SQLi payloads (MySQL SLEEP, PostgreSQL pg_sleep). Used double-sampled.
_SQLI_TIME = ("' AND SLEEP(5)-- -", "1 AND SLEEP(5)-- -", "';SELECT pg_sleep(5)-- -",
              "1) AND SLEEP(5)-- -")
# Stored-XSS marker (distinct from reflected) — injected once, hunted on OTHER pages.
_STORED_MARK = "jvz9stored"
# B5 destructive-endpoint guard: don't auto-fire state-changing requests on a live target
# (delete / reset / payment / logout / invite) without explicit opt-in — protects real targets
# from side effects + alert fatigue during multi-user replay.
_DESTRUCTIVE_PATH = re.compile(
    r"delete|remove|destroy|purge|drop|reset|logout|signout|sign-out|deactivate|disable|"
    r"cancel|revoke|password|passwd|payment|pay\b|charge|transfer|withdraw|refund|checkout|"
    r"invite|send|email|sms|otp|verify|2fa|wipe|truncate", re.I)


def _is_destructive(url: str, method: str = "GET") -> bool:
    """A request that likely changes server state / fires a notification / costs money."""
    if (method or "GET").upper() in ("DELETE", "PUT", "PATCH"):
        return True
    from urllib.parse import urlsplit
    return bool(_DESTRUCTIVE_PATH.search(urlsplit(url or "").path))


import time as _rg_time, threading as _rg_threading
_RATE_LOCK = _rg_threading.Lock()
_RATE_LAST = [0.0]


def _rate_gate(url: str = ""):
    """Pace EVERY outbound request to the program's rate limit (data/roe.json rate_limit_rps),
    enforced at the one seam all probe/crawl/idor/post loops flow through — so a strict
    bug-bounty cap (e.g. 1win = 5 req/s) is honored everywhere, not just nuclei. A conservative
    default (3 req/s) protects PUBLIC hosts if scope-setup was forgotten; localhost = unthrottled
    (dogfood speed). Single-threaded by design, so concurrency stays at 1 (well under any cap)."""
    try:
        from urllib.parse import urlsplit
        import ipaddress, json as _json, os as _os
        rps = 0.0
        try:
            roe = _json.load(open(_os.path.join("data", "roe.json"), encoding="utf-8"))
            rps = float(roe.get("rate_limit_rps") or 0)
        except Exception:
            rps = 0.0
        if not rps:                                   # no program limit set
            host = urlsplit(url).hostname or ""
            local = host in ("localhost", "127.0.0.1", "::1")
            try:
                local = local or ipaddress.ip_address(host).is_private
            except Exception:
                pass
            rps = 0.0 if local else 3.0               # safe default for public live targets
        if rps <= 0:
            return
        interval = 1.0 / rps
        with _RATE_LOCK:
            wait = interval - (_rg_time.time() - _RATE_LAST[0])
            if wait > 0:
                _rg_time.sleep(wait)
            _RATE_LAST[0] = _rg_time.time()
    except Exception:
        pass


def _http_get(url: str, timeout: int = 8, headers: dict = None, allow_redirects: bool = True):
    """Thin HTTP GET seam used by the injection probe (kept module-level so tests
    can patch it directly instead of monkeypatching global sys.modules).
    headers carries a session Cookie / auth header for authenticated targets;
    allow_redirects=False lets the open-redirect probe read the Location header."""
    import requests
    _rate_gate(url)
    return requests.get(url, timeout=timeout, headers=headers or None,
                        allow_redirects=allow_redirects)


def _http_post(url: str, data=None, json_body=None, timeout: int = 8, headers: dict = None):
    """POST seam for the POST-body injection probe (patchable in tests).
    data = form dict; json_body = JSON dict. headers carries the session."""
    import requests
    _rate_gate(url)
    return requests.post(url, data=data, json=json_body, timeout=timeout,
                         headers=headers or None)


def _http_write(method: str, url: str, json_body=None, timeout: int = 8, headers: dict = None):
    """PUT/PATCH/DELETE seam for the opt-in write-BOLA oracle (patchable in tests)."""
    import requests
    _rate_gate(url)
    return requests.request(method.upper(), url, json=json_body, timeout=timeout,
                            headers=headers or None)



# Param-name -> extra test type. Dork-derived (TakSec param classes): the param's
# NAME hints which class to test, so the probe doesn't fire every payload at every param.
_PARAM_HINTS = {
    "open-redirect": ("redirect", "redir", "url", "next", "return", "returnurl", "dest",
                      "destination", "continue", "goto", "out", "to", "link", "callback", "r2", "u"),
    "lfi": ("file", "page", "path", "include", "doc", "document", "template", "folder",
            "dir", "load", "download", "read", "filename", "pg"),
}
_LFI_PROBE = "../" * 10 + "etc/passwd"   # deep traversal — app nesting/mount depth is unknown
_LFI_SIGN = re.compile(r"root:.?:0:0:|\[boot loader\]|\[fonts\]")        # /etc/passwd or win.ini
_REDIR_MARKER = "jvz9redir.example"


def _xss_ctx_at(body: str, pos: int) -> str:
    """Classify the reflection context at ONE offset. Deterministic string-scan (no parser):
      'html'    — raw element context: `<x>` starts a tag → EXECUTABLE (escalatable to <svg onload>)
      'attr'    — inside a tag's attributes: needs a quote/bracket breakout → candidate, not proven
      'comment' — inside <!-- --> : inert unless the attacker can also inject `-->` → drop
      'rawtext' — inside script/style/title/textarea: `<x>` is literal text, no tag parse → drop
    """
    before = body[:pos]
    low = before.lower()
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment"
    for tag in ("script", "style", "title", "textarea"):
        if low.rfind("<" + tag) > low.rfind("</" + tag):
            return "rawtext"
    if before.rfind("<") > before.rfind(">"):     # unclosed '<' before us = inside a tag
        return "attr"
    return "html"


def _xss_reflection_ctx(body: str, marker: str) -> str:
    """Best (most-exploitable) context across ALL reflections of the marker. A value often
    echoes in several places (e.g. a JS var AND a visible `<b>...</b>`); the finding's confidence
    must reflect the STRONGEST context, not just the first occurrence. (Encoding already handled
    upstream: an HTML-encoded reflection is `&lt;x&gt;` so exact-match never fires.)"""
    rank = {"html": 3, "attr": 2, "comment": 0, "rawtext": 0}
    best, best_rank, start = "comment", -1, 0
    while True:
        pos = body.find(marker, start)
        if pos == -1:
            break
        c = _xss_ctx_at(body, pos)
        if rank[c] > best_rank:
            best, best_rank = c, rank[c]
        if c == "html":
            break                                 # nothing beats a raw-element reflection
        start = pos + 1
    return best


# Test-planner knowledge (SQLI_PAYLOADS / TEST_REFS) moved to agents/ultron/report.py (Phase B).

_KB_WORDLIST_DIR = os.path.join("agents", "ultron", "knowledge", "wordlists")

# Third-party / shared hosting — a host on these isn't yours to attack just because the
# app on it looks vulnerable; the infra owner hasn't consented (see scope discipline).
_SAAS_HOSTS = ("atlassian.net", "okta.com", "zendesk.com", "salesforce.com", "cloudfront.net",
               "azurewebsites.net", "herokuapp.com", "github.io", "myshopify.com", "wpengine.com",
               "netlify.app", "vercel.app", "firebaseapp.com", "s3.amazonaws.com")


def _load_scope() -> dict:
    """Load data/scope.json (cwd-relative). Accepts a bare list (= in_scope) or
    {in_scope, out_of_scope}. Returns {} when absent/invalid."""
    try:
        import json
        p = os.path.join("data", "scope.json")
        if not os.path.isfile(p):
            return {}
        raw = json.load(open(p, encoding="utf-8"))
        if isinstance(raw, list):
            return {"in_scope": raw, "out_of_scope": []}
        return {"in_scope": raw.get("in_scope", []), "out_of_scope": raw.get("out_of_scope", [])}
    except Exception:
        return {}


def _load_roe() -> dict:
    """Load data/roe.json (rules of engagement: out-of-scope vuln types, rate limit, rules).
    Written by setup_scope from a pasted program policy. {} when absent."""
    try:
        import json
        p = os.path.join("data", "roe.json")
        return json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else {}
    except Exception:
        return {}


def _host_score(rule: str, host: str) -> int:
    """Specificity score if `rule` matches `host`, else -1. Exact match outranks a wildcard;
    among the same kind the longer (deeper) domain is more specific — mirrors how bug-bounty
    programs resolve overlapping scope ('most specific wins')."""
    r = (rule or "").strip().lower()
    wild = r.startswith("*.")
    r = r.lstrip("*.").lstrip(".")
    if not r:
        return -1
    if host == r or host.endswith("." + r):
        return len(r) + (0 if wild else 1000)   # exact (+1000) always beats a wildcard
    return -1


def _in_scope(host: str) -> str:
    """'in' / 'out' / 'unknown' for a host, applying most-specific-wins between the in_scope
    and out_of_scope rule sets. 'unknown' = no scope.json, or no rule matched."""
    host = re.sub(r"^https?://", "", (host or "").strip().lower()).split("/")[0].split(":")[0]
    scope = _load_scope()
    if not host or not scope:
        return "unknown"
    best_in = max([_host_score(r, host) for r in scope.get("in_scope", [])], default=-1)
    best_out = max([_host_score(r, host) for r in scope.get("out_of_scope", [])], default=-1)
    if best_out >= 0 and best_out >= best_in:   # tie or a more-specific exclusion -> OUT
        return "out"
    if best_in >= 0:
        return "in"
    return "unknown"


_TARGET_WATCH = os.path.join("data", "target_watch.json")


def _load_target_watch() -> list:
    """Load the target monitor watchlist (data/target_watch.json). List of
    {target, snapshot, added, last_checked, last_change}. [] when absent."""
    try:
        import json
        return json.load(open(_TARGET_WATCH, encoding="utf-8")) if os.path.isfile(_TARGET_WATCH) else []
    except Exception:
        return []


def _save_target_watch(rows: list) -> None:
    import json
    os.makedirs("data", exist_ok=True)
    with open(_TARGET_WATCH, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)


def parse_scope(text: str) -> dict:
    """Read a pasted bug-bounty program policy (in-scope / out-of-scope prose) and extract
    structured rules of engagement via the local LLM. Returns the parsed dict (best-effort —
    LLM extraction, verify it). Domains feed the scope engine; out-of-scope vuln types feed
    the validation gate; rate_limit configures the tools."""
    import json as _json
    if not text or len(text.strip()) < 20:
        return {}
    prompt = (
        "You parse bug-bounty program policies into STRICT JSON for an automated tool. "
        "Output ONLY the JSON object, no prose, no markdown fences.\n\n"
        "Schema (use [] / null when not stated):\n"
        "{\n"
        '  "in_scope_domains": [],     // explicit domains/subdomains/wildcards IN scope, e.g. "accounts.example.com","*.example.com". named surfaces that are not domains -> skip.\n'
        '  "out_of_scope_domains": [], // explicit domains OUT of scope.\n'
        '  "in_scope_types": [],       // vuln classes explicitly wanted, short lowercase tags: auth-bypass, oauth, mfa-bypass, sqli, idor, ssrf, xss, account-takeover...\n'
        '  "out_of_scope_types": [],   // vuln classes NOT accepted, short tags: self-xss, clickjacking, framing, spf, dkim, dmarc, mitm, open-redirect, tls-version, open-ports, dns, missing-csrf, version-disclosure, scanner-noise, dos, social-engineering...\n'
        '  "rate_limit_rps": null,     // max requests/sec as a NUMBER if stated, else null.\n'
        '  "max_concurrent": null,     // max concurrent requests as a NUMBER if stated, else null.\n'
        '  "rules": []                 // short imperative testing rules to remember, e.g. "use only your own accounts", "contact-form subject must include Test", "no DoS".\n'
        "}\n\n"
        f"POLICY:\n{text[:6000]}\n\nJSON:"
    )
    try:
        raw = ask_llm(prompt, agent="ultron", autotune_on=False,
                      params={"temperature": 0.1, "num_predict": 700})
    except Exception as e:
        return {"_error": f"LLM parse failed: {e}"}
    raw = (raw or "").strip()
    if "```" in raw:                                  # strip code fences if the model adds them
        raw = re.sub(r"```(?:json)?", "", raw).strip()
    m = re.search(r"\{.*\}", raw, re.DOTALL)          # grab the JSON object
    if not m:
        return {"_error": "no JSON in LLM output", "_raw": raw[:200]}
    try:
        d = _json.loads(m.group(0))
    except Exception:
        return {"_error": "invalid JSON from LLM", "_raw": m.group(0)[:200]}
    # normalise
    out = {
        "in_scope_domains": [s.strip().lower() for s in (d.get("in_scope_domains") or []) if s],
        "out_of_scope_domains": [s.strip().lower() for s in (d.get("out_of_scope_domains") or []) if s],
        "in_scope_types": [s.strip().lower() for s in (d.get("in_scope_types") or []) if s],
        "out_of_scope_types": [s.strip().lower() for s in (d.get("out_of_scope_types") or []) if s],
        "rate_limit_rps": d.get("rate_limit_rps"),
        "max_concurrent": d.get("max_concurrent"),
        "rules": [s.strip() for s in (d.get("rules") or []) if s],
    }
    return out


def scope_filter(hosts: list) -> tuple:
    """Split hosts into (kept = in/unknown, dropped = out-of-scope). With no scope.json
    everything is kept (nothing dropped)."""
    keep, drop = [], []
    for h in hosts or []:
        (drop if _in_scope(h) == "out" else keep).append(h)
    return keep, drop


def _scope_check(target: str) -> str:
    """Advisory scope note for one target: OUT-of-scope (hard), not-in-scope.json, or a
    third-party SaaS host. Returns '' when all clear."""
    host = re.sub(r"^https?://", "", (target or "").strip().lower()).split("/")[0].split(":")[0]
    if not host:
        return ""
    notes = []
    verdict = _in_scope(host)
    if verdict == "out":
        notes.append(f"'{host}' is OUT OF SCOPE per data/scope.json — do NOT test it.")
    elif verdict == "unknown" and _load_scope():
        notes.append(f"'{host}' is not covered by data/scope.json — confirm it's authorized.")
    if any(host == s or host.endswith("." + s) for s in _SAAS_HOSTS):
        notes.append(f"'{host}' is third-party/shared (SaaS) hosting — only test if the program "
                     f"explicitly authorizes this exact asset.")
    return "  ".join(notes)


# Analyst reasoning discipline injected into report-synthesis prompts — keeps the local
# model concrete and low-hallucination (state evidence, never assert a finding without one).
_ANALYST_DISCIPLINE = (
    "Reason like a disciplined analyst — for every claim, work the loop: "
    "RECON (what the scan data actually shows — name the exact endpoint/header/response), "
    "HYPOTHESIS (which vulnerability class that evidence suggests), "
    "TEST (the minimal probe that separates a real bug from a false positive), "
    "CONFIRM (is a concrete indicator present in the data?). "
    "NEVER state a finding without a concrete indicator from the results above; if the "
    "evidence isn't there, say so plainly and move on. No speculation, no filler."
)


def _clean_site(target: str) -> str:
    """Normalise a target into a tidy, filesystem-safe folder name.
    Old reports encoded dots as underscores (testaspnet_vulnweb_com); convert those
    back to a readable host, and strip Windows-invalid chars."""
    t = re.sub(r"^https?://", "", (target or "unknown").strip().lower()).rstrip("/")
    t = t.replace("_", ".")                       # underscored-domain -> dotted host
    t = re.sub(r'[\\/:*?"<>|]+', "-", t)          # drop chars Windows folders can't have
    return t.strip(". ") or "unknown"


# Two-part public suffixes where the registrable domain is the last THREE labels
# (e.g. example.co.uk, site.com.au). Everything else = last two labels.
_MULTI_TLDS = frozenset((
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "gov.au",
    "edu.au", "co.nz", "com.br", "com.sg", "com.my", "com.tr", "com.mx", "com.ar", "com.cn",
    "co.jp", "co.kr", "co.za", "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "gov.in", "ac.in", "edu.in", "res.in", "co.il", "co.id", "or.id", "ac.id", "com.hk",
    "com.ph", "com.vn", "com.eg", "com.sa", "com.ng", "com.pk", "com.bd", "com.ua", "ac.ae",
    "co.ae", "gov.ae", "net.ae", "org.ae", "sch.ae", "mil.ae",
))


def _apex_domain(target: str) -> str:
    """The registrable (apex / eTLD+1) domain for a host. Subfinder must run on the APEX —
    given 'www.bhavansdubai.com' it enumerates '*.www.bhavansdubai.com' = nothing, so we
    strip down to 'bhavansdubai.com'. Handles two-part TLDs (example.co.uk -> example.co.uk)."""
    host = re.sub(r"^https?://", "", (target or "").strip().lower()).split("/")[0].split(":")[0]
    host = host.strip(".")
    if not host or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):   # empty or an IP -> unchanged
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _sitemap_paths(base_url: str) -> list:
    """PASSIVE path discovery (cheap: a few GETs): robots.txt 'Sitemap:' lines + /sitemap.xml,
    following nested sitemap indexes. WordPress/CMS list every published page here — the fast
    way to the real path surface without brute-force. Returns absolute page URLs."""
    import re as _re
    # a browser UA — WP/CMS bot-plugins serve an EMPTY body for sitemap.xml to 'python-requests'.
    _ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    def fetch(u):
        try:
            return _http_get(u, timeout=8, headers=_ua).text or ""
        except Exception:
            return ""
    base = base_url.rstrip("/")
    seeds = _re.findall(r"(?im)^\s*sitemap:\s*(\S+)", fetch(base + "/robots.txt"))
    seeds.append(base + "/sitemap.xml")
    seeds.append(base + "/sitemap_index.xml")
    queue = list(dict.fromkeys(seeds))
    out, seen = set(), set()
    for _ in range(15):                                    # cap sitemap fetches
        if not queue:
            break
        sm = queue.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        for loc in _re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", fetch(sm)):
            if loc.lower().endswith(".xml") and "sitemap" in loc.lower():
                if loc not in seen:
                    queue.append(loc)                      # nested sitemap index
            elif loc.startswith("http"):
                out.add(loc)
    return sorted(out)


def _report_type_target(name: str) -> tuple:
    """Split a save_report `name` into (type-label, target). full_recon passes a bare
    target; full_pipeline/bug_bounty/find_exploits prefix it with their type."""
    n = (name or "").strip()
    for pfx, label in (("pipeline_", "pipeline"), ("bugbounty_", "bugbounty"),
                       ("exploits_", "exploits")):
        if n.lower().startswith(pfx):
            return label, n[len(pfx):]
    return "recon", n


def _parse_nuclei_findings(raw: str) -> list:
    """Parse nuclei output lines -> structured findings.
    Nuclei format: [template-id] [protocol] [severity] url [extra]"""
    findings = []
    if not raw:
        return findings
    import re as _re
    for line in raw.splitlines():
        line = _re.sub(r"\x1b\[[0-9;]*m", "", line).strip()   # strip ANSI color (nuclei colorizes ids)
        if not line or line.startswith(("[INF]", "[WRN]", "[ERR]", "[FTL]")):
            continue
        tags = _re.findall(r"\[([^\]]+)\]", line)
        if len(tags) < 2:
            continue
        template = tags[0].strip()
        severity = next(
            (t.lower() for t in tags if t.lower() in _SEV_ORDER), "info"
        )
        url_m = _re.search(r"(https?://\S+)", line)
        cve_m = _re.search(r"(CVE-\d{4}-\d{4,7})", line, _re.IGNORECASE)
        findings.append({
            "template": template,
            "severity": severity,
            "url": url_m.group(1) if url_m else "",
            "cve": cve_m.group(1).upper() if cve_m else None,
        })
    # de-dupe by (template, url)
    seen, out = set(), []
    for f in findings:
        key = (f["template"], f["url"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    out.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))
    return out


def _parse_nuclei_voice(raw: str, target: str) -> str:
    """Convert nuclei output to severity-grouped voice summary."""
    if not raw or not raw.strip():
        return f"Nuclei found no vulnerabilities on {target}."
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for line in raw.splitlines():
        ll = line.lower()
        for sev in by_severity:
            if f"[{sev}]" in ll:
                # Extract template ID (first bracketed token)
                import re as _re
                m = _re.search(r"\[([^\]]+)\]", line)
                if m:
                    by_severity[sev].append(m.group(1))
                break
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        if by_severity[sev]:
            parts.append(f"{len(by_severity[sev])} {sev}")
    if not parts:
        return f"Nuclei completed scan on {target}. No significant findings."
    return f"Nuclei found vulnerabilities on {target}: {', '.join(parts)}."


class UltronAgent:
    """
    Ultron - Security Agent

    Capabilities:
    - Nmap port scan (basic/quick/service/full)
    - Subfinder subdomain enum
    - Httpx HTTP probe
    - Nuclei vulnerability scan (with severity filter)
    - Full recon workflow
    - System health
    - File risk scan
    - Log check
    - LLM risk summary
    - Auto-save reports to Desktop (.md + .html)

    SAFE RULE: Own systems / authorized targets only.
    """

    def __init__(self):
        self._last_report_md = None
        self._last_report_name = None

    # =====================================
    # SAVE REPORT
    # =====================================
    def save_report(self, name: str, content: str) -> str:
        try:
            typ, target = _report_type_target(name)
            site = _clean_site(target)
            folder = os.path.join(os.path.expanduser("~"), "Desktop", "Ultron Reports", site)
            os.makedirs(folder, exist_ok=True)
            date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
            filename = f"{typ}_{date_str}.md"
            filepath = os.path.join(folder, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

            self._write_site_index(folder, site)   # refresh the folder's navigation index

            # Store for HTML export
            self._last_report_md = content
            self._last_report_name = f"{site}_{typ}"

            return filepath
        except Exception:
            return None

    def _write_site_index(self, folder: str, site: str) -> None:
        """(Re)write _index.md — a newest-first table of every report/screenshot in this
        target's folder, so anyone opening it can navigate at a glance."""
        try:
            items = []
            for fn in os.listdir(folder):
                if fn == "_index.md" or fn.startswith("."):
                    continue
                fp = os.path.join(folder, fn)
                if os.path.isfile(fp):
                    items.append((os.path.getmtime(fp), fn))
            items.sort(reverse=True)
            lines = [f"# Ultron Reports — {site}", "",
                     f"_{len(items)} file(s) · newest first · updated "
                     f"{datetime.datetime.now():%Y-%m-%d %H:%M}_", "",
                     "| Type | File | When |", "|------|------|------|"]
            for mt, fn in items:
                typ = fn.split("_", 1)[0]
                when = datetime.datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M")
                lines.append(f"| {typ} | [{fn}]({fn}) | {when} |")
            with open(os.path.join(folder, "_index.md"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception as e:
            print(f"[ULTRON] index refresh skipped: {e}")

    # =====================================
    # EXPORT HTML
    # =====================================
    def export_html(self) -> dict:
        if not self._last_report_md:
            return {"success": False, "message": "No report to export. Run a scan first.", "data": {}}
        try:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ultron_{self._last_report_name}_{date_str}.html"
            filepath = os.path.join(desktop, filename)
            html = report.md_to_html(self._last_report_md, f"Ultron Report — {self._last_report_name}")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            return {"success": True, "message": f"HTML report saved to Desktop: {filename}", "data": {"path": filepath}}
        except Exception as e:
            return {"success": False, "message": f"HTML export failed: {e}", "data": {}}

    # =====================================
    # NMAP SCAN
    # =====================================
    def nmap_scan(self, target: str, scan_type: str = "basic") -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Nmap scan: {target} ({scan_type})")
        _sc = _scope_check(target)
        if _sc:
            print(f"[ULTRON][SCOPE] {_sc}")

        # Flags by scan type
        flags = {
            "basic": ["-F", "-T4"],
            "full": ["-sV", "-T4", "-p-"],
            "quick": ["-F", "-T5"],
            "service": ["-sV", "-T4"]
        }

        args = flags.get(scan_type, ["-F", "-T4"])
        output = run_cmd(["nmap"] + args + [target], timeout=120)

        if "Tool not found" in output:
            return {
                "success": False,
                "message": "Nmap not installed. Install: https://nmap.org",
                "data": {}
            }

        voice_summary = _parse_nmap_voice(output, target)

        # Scan diffing — compare to previous scan of same target
        try:
            diff = _diff_scan(target, scan_type, output)
            if diff:
                voice_summary += " " + diff
        except Exception as e:
            print(f"[ULTRON] scan diff error: {e}")

        return {
            "success": True,
            "message": voice_summary,
            "data": {"target": target, "scan_type": scan_type, "raw": output}
        }

    # =====================================
    # SUBFINDER
    # =====================================
    def subfinder(self, domain: str) -> dict:

        if not domain:
            return {"success": False, "message": "Domain missing.", "data": {}}

        # subfinder enumerates CHILDREN of what it's given — run it on the registrable APEX
        # so 'www.x.com' (or any subdomain) finds the whole domain's subs, not '*.www.x.com'.
        domain = _apex_domain(domain)
        print(f"[ULTRON] Subfinder: {domain}")
        output = run_cmd(["subfinder", "-d", domain, "-silent"], timeout=60)

        if "Tool not found" in output:
            return {
                "success": False,
                "message": "Subfinder not installed. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "data": {}
            }

        subdomains = [s for s in output.splitlines() if s.strip()]

        if not subdomains:
            return {
                "success": True,
                "message": f"No subdomains found for {domain}.",
                "data": {"domain": domain, "subdomains": []}
            }

        msg = f"Found {len(subdomains)} subdomains for {domain}:\n" + "\n".join(subdomains[:30])

        if len(subdomains) > 30:
            msg += f"\n...and {len(subdomains) - 30} more"

        return {
            "success": True,
            "message": msg,
            "data": {"domain": domain, "subdomains": subdomains}
        }

    # =====================================
    # HTTPX PROBE
    # =====================================
    def httpx_probe(self, target: str) -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Httpx probe: {target}")
        output = run_cmd(
            ["httpx", "-u", _ipv4_local(target), "-title", "-status-code", "-tech-detect", "-silent", "-nc"],
            timeout=30
        )

        if "Tool not found" in output:
            return {
                "success": False,
                "message": "Httpx not installed. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "data": {}
            }

        return {
            "success": True,
            "message": output or f"No HTTP response from {target}.",
            "data": {"target": target, "raw": output}
        }

    # =====================================
    # NUCLEI SCAN
    # =====================================
    def nuclei_scan(self, target: str, severity: str = "medium,high,critical", cookie: str = "") -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Nuclei scan: {target} (severity: {severity})")

        cmd = ["nuclei", "-u", _ipv4_local(target), "-severity", severity, "-silent", "-nc"]
        if cookie:                                       # authenticated scan — carry the session
            cmd += ["-H", f"Cookie: {cookie}"]
        _rl = _load_roe().get("rate_limit_rps")          # honor a program's request-rate cap
        if _rl:
            cmd += ["-rl", str(int(_rl)), "-c", str(int(_load_roe().get("max_concurrent") or 5))]
            print(f"[ULTRON][SCOPE] rate-limited to {_rl} req/s per program policy.")
        output = run_cmd(cmd, timeout=180)

        if "Tool not found" in output:
            return {
                "success": False,
                "message": "Nuclei not installed. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "data": {}
            }

        voice_summary = _parse_nuclei_voice(output, target)
        return {
            "success": True,
            "message": voice_summary,
            "data": {"target": target, "severity": severity, "raw": output}
        }

    # =====================================
    # EXPLOIT POC FINDER (Phase 25)
    # =====================================
    def find_exploits(self, cve_id: str) -> dict:
        return cve_lookup.find_exploits(cve_id, save_report=self.save_report)

    # =====================================
    # KATANA CRAWL (Phase 24)
    # =====================================
    def katana_crawl(self, target: str, depth: int = 3) -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        url = _resolve_scheme(target)
        print(f"[ULTRON] Katana crawl: {url} (depth={depth})")

        output = run_cmd(
            ["katana", "-u", url, "-depth", str(depth), "-silent", "-no-color"],
            timeout=120
        )

        if "Tool not found" in output or not output:
            not_installed = "Tool not found" in output
            if not_installed:
                return {
                    "success": False,
                    "message": "Katana not installed. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
                    "data": {}
                }
            return {"success": True, "message": f"Katana found no URLs on {target}.", "data": {"urls": []}}

        urls = [u.strip() for u in output.splitlines() if u.strip().startswith("http")]

        if not urls:
            return {"success": True, "message": f"Katana found no crawlable URLs on {target}.", "data": {"urls": []}}

        summary = f"Katana crawled {len(urls)} URLs on {target}."
        preview = "\n".join(urls[:20])
        if len(urls) > 20:
            preview += f"\n...and {len(urls)-20} more"

        return {
            "success": True,
            "message": f"{summary}\n{preview}",
            "data": {"target": target, "urls": urls, "count": len(urls)}
        }

    # =====================================
    # SCREENSHOT (Phase 24)
    # =====================================
    def take_screenshot(self, target: str) -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        try:
            from playwright.sync_api import sync_playwright

            folder = os.path.join(os.path.expanduser("~"), "Desktop", "Ultron Reports",
                                  _clean_site(target))
            os.makedirs(folder, exist_ok=True)
            date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
            filename = f"screenshot_{date_str}.png"
            filepath = os.path.join(folder, filename)

            print(f"[ULTRON] Screenshot: {url}")

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1280, "height": 900})
                page.goto(url, timeout=15000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                page.screenshot(path=filepath, full_page=False)
                browser.close()

            return {
                "success": True,
                "message": f"Screenshot saved: {filepath}",
                "data": {"path": filepath, "url": url}
            }

        except ImportError:
            return {"success": False, "message": "Playwright not installed.", "data": {}}
        except Exception as e:
            return {"success": False, "message": f"Screenshot failed: {e}", "data": {}}

    # =====================================
    # CONTENT DISCOVERY (brute hidden paths/dirs crawling misses)
    # =====================================
    def content_discovery(self, target: str, wordlist: str = "", timeout: int = 180) -> dict:
        """Brute-force hidden paths/dirs. Tries ffuf -> gobuster -> feroxbuster (first one
        installed), bundled wordlist by default. Graceful when no tool present. Found paths
        are recorded to the target profile so they feed later probing. Authorized targets only."""
        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}
        import shutil
        base = _resolve_scheme(target)
        wl = wordlist or os.path.join(_KB_WORDLIST_DIR, "common_dirs.txt")
        if not os.path.isfile(wl):
            return {"success": False, "message": f"wordlist not found: {wl}", "data": {}}
        wl = os.path.abspath(wl).replace("\\", "/")   # fwd slashes — Windows backslashes trip the arg sanitizer

        found, tool = [], None
        _maxtime = str(max(timeout - 5, 10))         # let the tool self-stop before run_cmd's kill
        def _is_err(o):                               # error sentinel from run_cmd (empty = 0 found, NOT error)
            return (o or "").strip().startswith(("Tool not found", "Refused", "Timed out", "Error", "__"))
        _rl = _load_roe().get("rate_limit_rps")          # honor a program's request-rate cap
        if shutil.which("ffuf"):
            tool = "ffuf"
            import tempfile, json as _json
            _of = os.path.join(tempfile.gettempdir(), f"ffuf_{os.getpid()}.json").replace("\\", "/")
            _ff = ["ffuf", "-u", base.rstrip("/") + "/FUZZ", "-w", wl,
                   "-mc", "200,204,301,302,307,401,403", "-ac", "-t", "20",
                   "-maxtime", _maxtime, "-of", "json", "-o", _of]
            if _rl:
                _ff += ["-rate", str(int(_rl))]
            out = run_cmd(_ff, timeout=timeout)
            if _is_err(out) and not os.path.isfile(_of):
                return {"success": False, "message": f"ffuf: {out.strip()[:90]}", "data": {"found": []}}
            try:                                  # parse ffuf's structured JSON (no text-noise)
                with open(_of, encoding="utf-8") as fh:
                    for res in _json.load(fh).get("results", []):
                        u = res.get("url", "")
                        if u:
                            found.append(u.split("#")[0])
            except Exception:
                pass
            finally:
                try:
                    os.remove(_of)
                except Exception:
                    pass
        elif shutil.which("gobuster"):
            tool = "gobuster"
            out = run_cmd(["gobuster", "dir", "-u", base, "-w", wl, "-q", "-t", "20"], timeout=timeout)
            if _is_err(out):
                return {"success": False, "message": f"gobuster: {out.strip()[:90]}", "data": {"found": []}}
            for ln in out.splitlines():
                m = re.match(r"(/\S+)\s+\(Status:\s*\d+\)", ln.strip())
                if m:
                    found.append(base.rstrip("/") + m.group(1))
        elif shutil.which("feroxbuster"):
            tool = "feroxbuster"
            out = run_cmd(["feroxbuster", "-u", base, "-w", wl, "--silent", "-t", "40"], timeout=timeout)
            if _is_err(out):
                return {"success": False, "message": f"feroxbuster: {out.strip()[:90]}", "data": {"found": []}}
            for ln in out.splitlines():
                ln = ln.strip()
                if ln.startswith("http"):
                    found.append(ln.split()[-1])
        else:
            return {"success": False,
                    "message": "No content-discovery tool found — install ffuf, gobuster, or feroxbuster.",
                    "data": {"found": []}}

        found = sorted(set(found))
        try:
            from core import target_profiles
            if found:
                target_profiles.record_endpoints(_clean_site(target), found)
        except Exception:
            pass
        tail = ", ".join(p.rsplit("/", 1)[-1] for p in found[:10])
        return {"success": True,
                "message": f"{tool}: found {len(found)} path(s) on {base}" + (f": {tail}" if found else "."),
                "data": {"tool": tool, "found": found, "count": len(found)}}

    # =====================================
    # SPA RENDER-CRAWL (the attack surface a passive crawler can't see)
    # =====================================
    def spa_crawl(self, target: str, timeout: int = 30, interact: bool = True, cookie: str = "") -> dict:
        """Render a JS/SPA target in headless Chromium and capture its LIVE attack surface:
        rendered DOM links + every same-origin XHR/fetch API call the app makes — the real
        endpoints (e.g. /api/..., /rest/..., /graphql) that katana's passive crawl misses on
        React/Angular/Vue apps. Reuses the bundled Playwright; graceful if absent. Found
        endpoints are recorded to the target profile. Authorized targets only."""
        if not target:
            return {"success": False, "message": "Target missing.", "data": {"urls": []}}
        base = _resolve_scheme(target)
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return {"success": False, "data": {"urls": []},
                    "message": "Playwright not installed (pip install playwright && playwright install chromium)."}
        from urllib.parse import urlsplit, urljoin
        host = urlsplit(base).netloc
        apis, links = set(), set()
        posts, _post_seen = [], set()            # POST/PUT endpoints (url+body) for the POST probe
        print(f"[ULTRON] SPA render-crawl: {base}")
        try:
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True)
                page = b.new_page()
                if cookie:                       # authenticated crawl — carry the session
                    page.set_extra_http_headers({"Cookie": cookie})

                def _on_req(r):
                    try:
                        if r.resource_type in ("xhr", "fetch") and urlsplit(r.url).netloc == host:
                            # drop websocket transport polling (/socket.io/?EIO=..&t=..&sid=..) —
                            # not a testable API endpoint, and its volatile sids spam the surface.
                            if "/socket.io/" in r.url or "transport=polling" in r.url:
                                return
                            u = r.url.split("#")[0]
                            apis.add(u)
                            # capture POST/PUT/PATCH bodies — the real auth/mutation endpoints
                            # (login, search, GraphQL) the POST probe needs (NoSQL auth-bypass etc).
                            if r.method in ("POST", "PUT", "PATCH"):
                                pd = r.post_data
                                if pd and (u, pd) not in _post_seen and len(posts) < 25:
                                    _post_seen.add((u, pd))
                                    posts.append({"url": u, "method": r.method, "body": pd,
                                                  "ctype": (r.headers or {}).get("content-type", "")})
                    except Exception:
                        pass
                page.on("request", _on_req)
                page.goto(base, wait_until="networkidle", timeout=timeout * 1000)
                page.wait_for_timeout(2500)            # let late XHRs fire
                for a in page.query_selector_all("a[href]"):
                    href = (a.get_attribute("href") or "").strip()
                    if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                        continue
                    full = href if href.startswith("http") else urljoin(base, href)
                    if urlsplit(full).netloc == host:
                        links.add(full.split("#")[0])

                # Bounded interaction: type into visible search/text inputs and submit, so
                # endpoints that only fire on USER action (search XHRs, form GETs) surface too.
                # Same _on_req handler captures them. Capped + wrapped — never breaks the crawl.
                if interact:
                    try:
                        boxes = page.query_selector_all(
                            "input[type=search], input[type=text], input:not([type]), "
                            "input[name*=q], input[name*=search], input[placeholder*=earch]")
                        for el in boxes[:5]:
                            try:
                                el.fill("test")
                                el.press("Enter")
                                page.wait_for_timeout(500)
                                # a form GET navigates to ?param=...; capture that param'd URL
                                # (form-app vuln pages, e.g. DVWA sqli/?id=, never appear as a link).
                                cur = page.url.split("#")[0]
                                if "?" in cur and urlsplit(cur).netloc == host:
                                    apis.add(cur)
                            except Exception:
                                continue
                        page.wait_for_timeout(800)        # let interaction XHRs land
                    except Exception:
                        pass
                b.close()
        except Exception as e:
            return {"success": False, "data": {"urls": []},
                    "message": f"SPA crawl failed (target slow/unreachable?): {str(e)[:80]}"}
        allu = sorted(set(links) | set(apis))
        try:
            from core import target_profiles
            if allu:
                target_profiles.record_endpoints(_clean_site(target), allu)
        except Exception:
            pass
        return {"success": True,
                "message": f"SPA render-crawl: {len(links)} link(s) + {len(apis)} API endpoint(s)"
                           + (f" + {len(posts)} POST endpoint(s)" if posts else "") + f" on {base}.",
                "data": {"urls": allu, "links": sorted(links), "apis": sorted(apis),
                         "post_endpoints": posts, "count": len(allu)}}

    def crawl_site(self, target: str, max_pages: int = 25, max_depth: int = 2,
                   cookie: str = "", headers: dict = None) -> dict:
        """Bounded same-origin BFS crawl: follow <a href> links from the root, collect every
        parameterized URL across pages. The root-only crawl misses per-module vuln pages
        (DVWA open_redirect lives at /open_redirect/source/low.php?redirect=) — this walks the
        site so the probes see the WHOLE param surface, not just the landing page. HTTP-fetch
        (fast) + bs4 link extraction; pairs with spa_crawl (which renders the root for XHR).
        Authorized targets only."""
        import time
        from urllib.parse import urlsplit, urljoin, urldefrag
        try:
            import requests  # noqa: F401
            from bs4 import BeautifulSoup
        except Exception:
            return {"success": False, "message": "requests/bs4 unavailable.", "data": {"urls": []}}
        base = _resolve_scheme(target)
        host = urlsplit(base).netloc
        _hdrs = dict(headers or {})
        if cookie:
            _hdrs["Cookie"] = cookie
        seen, params, queue = set(), set(), [(base, 0)]
        pages = 0
        print(f"[ULTRON] Multi-page crawl: {base} (<= {max_pages} pages, depth {max_depth})")
        while queue and pages < max_pages:
            url, depth = queue.pop(0)
            url = urldefrag(url)[0]
            if url in seen:
                continue
            seen.add(url)
            try:
                r = _http_get(url, headers=_hdrs, timeout=8)
            except Exception:
                continue
            pages += 1
            if "?" in url:
                params.add(url)
            ctype = ""
            try:
                ctype = (r.headers.get("Content-Type") or "").lower()
            except Exception:
                pass
            if "html" not in ctype and "<" not in (r.text or "")[:200]:
                continue
            if depth >= max_depth:
                continue
            try:
                soup = BeautifulSoup(r.text or "", "html.parser")
            except Exception:
                continue
            for a in soup.find_all("a", href=True):
                href = (a["href"] or "").strip()
                if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                full = urldefrag(urljoin(url, href))[0]
                if urlsplit(full).netloc != host:
                    continue
                if "?" in full:
                    params.add(full)
                if full not in seen:
                    queue.append((full, depth + 1))
            # also harvest param'd URLs from <form action>+inputs (GET forms)
            for form in soup.find_all("form"):
                act = urljoin(url, (form.get("action") or url))
                names = [i.get("name") for i in form.find_all(("input", "select", "textarea")) if i.get("name")]
                if names and urlsplit(act).netloc == host and (form.get("method") or "get").lower() == "get":
                    params.add(act + ("&" if "?" in act else "?") + "&".join(f"{n}=1" for n in names[:6]))
            time.sleep(0.05)
        allp = sorted(params)
        try:
            from core import target_profiles
            if allp:
                target_profiles.record_endpoints(_clean_site(target), allp)
        except Exception:
            pass
        return {"success": True,
                "message": f"Multi-page crawl: {pages} page(s), {len(allp)} parameterized URL(s) on {base}.",
                "data": {"urls": allp, "pages": pages, "count": len(allp)}}

    # =====================================
    # FULL PIPELINE (Phase 24)
    # Nmap -> Subfinder -> Httpx -> Nuclei -> Katana -> Screenshot
    # =====================================
    def full_pipeline(self, target: str, cookie: str = "", discover: bool = False) -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Full pipeline: {target}")
        _sc = _scope_check(target)
        if _sc:
            print(f"[ULTRON][SCOPE] {_sc}")

        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        sections = {}

        # ── Stage 1: Nmap ──
        print("[ULTRON] Stage 1/5: Nmap...")
        nmap_r = self.nmap_scan(target, "basic")
        sections["nmap"] = nmap_r.get("data", {}).get("raw") or nmap_r.get("message", "Failed.")

        # ── Stage 2: Subfinder ──
        print("[ULTRON] Stage 2/5: Subfinder...")
        sub_r = self.subfinder(target)
        sections["subfinder"] = sub_r.get("message", "Failed.")
        subdomains = sub_r.get("data", {}).get("subdomains", [])
        # Scope filter — drop any out-of-scope subdomains so the pipeline never touches them
        subdomains, _oos = scope_filter(subdomains)
        if _oos:
            sections["subfinder"] += f"  [SCOPE: dropped {len(_oos)} out-of-scope: {', '.join(_oos[:5])}]"
            print(f"[ULTRON][SCOPE] dropped {len(_oos)} out-of-scope subdomain(s).")

        # ── Stage 3: Httpx ── (resolve http/https, don't force https)
        print("[ULTRON] Stage 3/5: Httpx...")
        base_url = _resolve_scheme(target)
        httpx_r = self.httpx_probe(base_url)
        sections["httpx"] = httpx_r.get("message", "Failed.")
        reachable = bool(httpx_r.get("data", {}).get("raw", "").strip())

        # ── Stage 4: Nuclei ──
        print("[ULTRON] Stage 4/5: Nuclei...")
        nuclei_r = self.nuclei_scan(base_url, cookie=cookie)
        sections["nuclei"] = nuclei_r.get("data", {}).get("raw") or nuclei_r.get("message", "No findings.")

        # ── Stage 5: Katana ──
        print("[ULTRON] Stage 5/5: Katana + Screenshot...")
        katana_r = self.katana_crawl(target)
        sections["katana"] = katana_r.get("message", "Skipped.")
        urls = katana_r.get("data", {}).get("urls", [])

        # Multi-page BFS crawl: follow links so per-module vuln pages (sub-paths) are in scope,
        # not just the landing page — katana's passive pass often stays shallow on server-rendered apps.
        post_endpoints = []
        try:
            mc = self.crawl_site(target, cookie=cookie)
            mc_urls = mc.get("data", {}).get("urls", [])
            if mc_urls:
                urls = sorted(set(urls) | set(mc_urls))
                sections["katana"] = (sections.get("katana", "") + "  |  " + mc.get("message", "")).strip()
                print(f"[ULTRON] multi-page enrichment: surface now {len(urls)} endpoint(s).")
        except Exception as e:
            print(f"[ULTRON] multi-page crawl skipped: {e}")

        # SPA fallback: a passive crawl returning ~nothing usually means a JS app — render it
        # in headless Chromium and capture the live API surface (+ POST endpoints) katana can't see.
        if len([u for u in urls if "?" in u or u.count("/") > 3]) < 3:
            spa = self.spa_crawl(target, cookie=cookie)
            spa_urls = spa.get("data", {}).get("urls", [])
            post_endpoints = spa.get("data", {}).get("post_endpoints", [])
            if spa_urls:
                urls = sorted(set(urls) | set(spa_urls))
                sections["katana"] = (sections.get("katana", "") + "  |  " + spa.get("message", "")).strip()
                print(f"[ULTRON] SPA enrichment: surface now {len(urls)} endpoint(s).")

        # ── Sitemap discovery (PASSIVE, always-on): robots.txt + sitemap.xml list real pages ──
        try:
            _sm = _sitemap_paths(base_url)
            if _sm:
                urls = sorted(set(urls) | set(_sm))
                sections["sitemap"] = f"{len(_sm)} page(s) from sitemap.xml / robots.txt."
                print(f"[ULTRON] Sitemap: +{len(_sm)} page(s); surface now {len(urls)}.")
            else:
                sections["sitemap"] = "No sitemap.xml / robots.txt paths found."
        except Exception as e:
            sections["sitemap"] = f"Sitemap discovery skipped: {e}"

        # ── Content discovery (ffuf/gobuster) — OPT-IN (slow/noisy; off by default) ──
        if discover:
            print("[ULTRON] Content discovery (opt-in): ffuf/gobuster...")
            try:
                _cd = self.content_discovery(target)
                _found = _cd.get("data", {}).get("found", [])
                sections["discovery"] = _cd.get("message", "no output")
                if _found:
                    _b = base_url.rstrip("/")
                    urls = sorted(set(urls) | set(
                        (p if p.startswith("http") else f"{_b}/{p.lstrip('/')}") for p in _found))
                    print(f"[ULTRON] Content discovery: +{len(_found)} path(s); surface now {len(urls)}.")
            except Exception as e:
                sections["discovery"] = f"Content discovery skipped: {e}"
        else:
            sections["discovery"] = "Skipped (opt-in — pass --discover / discover=True to run ffuf/gobuster)."

        # ── Screenshot ──
        shot_r = self.take_screenshot(base_url)
        shot_path = shot_r.get("data", {}).get("path", "")
        sections["screenshot"] = shot_r.get("message", "Screenshot failed.")

        # ── LLM Analysis ──
        print("[ULTRON] LLM analysis...")

        context = f"""Target: {target}

=== NMAP PORT SCAN ===
{sections['nmap'][:1200]}

=== SUBDOMAINS ===
{sections['subfinder'][:600]}

=== HTTP PROBE ===
{sections['httpx'][:400]}

=== VULNERABILITY SCAN ===
{sections['nuclei'][:1200]}

=== CRAWLED URLS (Katana) ===
{chr(10).join(urls[:30]) or 'No URLs crawled.'}
"""

        prompt = f"""You are Ultron, a cybersecurity analysis AI. Analyze these full recon pipeline results.

{context}

Write a structured security assessment:
1. Target Overview
2. Open Ports & Services
3. Subdomains & Attack Surface
4. HTTP/HTTPS Analysis
5. Vulnerabilities Detected
6. Crawled Endpoints of Interest
7. Risk Assessment (Low/Medium/High/Critical)
8. Recommendations

Technical, precise, actionable. No markdown # headers. Plain section labels.

{_ANALYST_DISCIPLINE}
{"" if reachable else '''
CRITICAL — INCONCLUSIVE: the HTTP probe returned NO response; the target was not reachable
from this host. Treat all empty results as TOOL FAILURE, not safety. Set Risk Assessment to
"Inconclusive - target unreachable" and advise re-running with egress to the target. Never rate Low.'''}
Report:"""

        analysis = ask_llm(prompt, agent="ultron")
        analysis = _critic_refine(prompt, analysis, agent="ultron")  # Phase 57 (gated)

        # ── Build report ──
        bb_banner = "" if reachable else (
            "> **INCONCLUSIVE — target unreachable from scan host.** Empty results below mean the "
            "scanners could not connect, not that the target is clean. Re-run with egress to target.\n\n")
        full_report = f"""# Ultron Full Pipeline Report: {target}

{bb_banner}**Target:** {target}
**Generated:** {date_str}
**Pipeline:** Nmap -> Subfinder -> Httpx -> Nuclei -> Katana -> Screenshot

---

## RAW DATA

### Nmap
{sections['nmap']}

### Subfinder
{sections['subfinder']}

### Httpx
{sections['httpx']}

### Nuclei
{sections['nuclei']}

### Katana (Crawled URLs)
{chr(10).join(urls[:50]) or 'None'}

### Sitemap / robots.txt
{sections.get('sitemap', 'n/a')}

### Content Discovery (ffuf/gobuster)
{sections.get('discovery', 'n/a')}

### Screenshot
{sections['screenshot']}

---

## ANALYSIS

{analysis or 'LLM analysis unavailable.'}

---
*Generated by JARVIS Ultron Full Pipeline — Phase 24*
"""

        saved_md = self.save_report(f"pipeline_{target}", full_report)
        save_msg = f"Report saved: {saved_md}" if saved_md else "Could not save report."

        # Voice summary
        nmap_voice = _parse_nmap_voice(sections["nmap"], target)
        nuclei_voice = _parse_nuclei_voice(sections["nuclei"], target)
        katana_count = len(urls)
        voice = (
            f"Full pipeline complete on {target}. "
            f"{nmap_voice} "
            f"{nuclei_voice} "
            f"Katana crawled {katana_count} URLs. "
            f"{save_msg}"
        )

        return {
            "success": True,
            "message": voice,
            "data": {
                "target": target,
                "sections": sections,
                "urls": urls,
                "post_endpoints": post_endpoints,
                "screenshot": shot_path,
                "saved_path": saved_md,
                "full_report": full_report
            }
        }

    # =====================================
    # BUG-BOUNTY WORKFLOW (Phase 54)
    # =====================================
    # =====================================
    # BURP INGEST (Phase 63 — Community-friendly)
    # =====================================
    def ingest_burp(self, path: str) -> dict:
        """Parse a Burp HTTP-history XML export -> endpoint inventory -> target profile."""
        from core import burp_ingest, target_profiles
        if not path:
            return {"success": False, "message": "Point me at a Burp export: 'ingest burp <file.xml>'.", "data": {}}
        res = burp_ingest.parse_export(path)
        if not res.get("success"):
            return res
        inv = res["data"]
        tags = inv.get("tags", {})
        # attach endpoints + typed intel to each host's profile
        for host in inv.get("hosts", []):
            host_urls = [u for u in inv.get("urls", []) if host in u]
            target_profiles.record_endpoints(host, host_urls)
            target_profiles.record_scan(host, "burp-ingest",
                                        f"{len(host_urls)} endpoints from Burp traffic")
            # Phase 64 — typed buckets (URL buckets filtered to host; tech is host-agnostic)
            host_tags = {b: [v for v in vals if host in v or b == "tech"]
                         for b, vals in tags.items()}
            target_profiles.record_tags(host, host_tags)
        res["message"] += " Saved to target profile(s). Next: nuclei/httpx on these endpoints."
        return res

    # =====================================
    # EVIDENCE / RETEST (Phase 64) — finding -> retest -> evidence -> report
    # =====================================
    def collect_evidence(self, url: str, label: str = "") -> dict:
        """Re-probe a finding URL and capture request/response evidence for the report."""
        from core import target_profiles
        if not url:
            return {"success": False, "message": "Give me a URL to validate, boss.", "data": {}}
        url = url.strip()
        probe = self.httpx_probe(url)          # live re-probe (httpx, already allowlisted)
        live = probe.get("message", "").strip()
        confirmed = probe.get("success") and bool(live) and "0 live" not in live.lower()
        evidence = (f"Retest of {url}\n"
                    f"Status: {'CONFIRMED live' if confirmed else 'no response / not reproduced'}\n"
                    f"Probe: {live[:400] or '(no output)'}")
        host = url.split("//")[-1].split("/")[0]
        target_profiles.record_evidence(host, label or url, evidence)
        return {"success": True,
                "message": (f"Evidence captured for {url} — "
                            f"{'confirmed live' if confirmed else 'could not reproduce'}. "
                            f"Saved to {host}'s profile."),
                "data": {"url": url, "confirmed": confirmed, "evidence": evidence}}

    # VALIDATION GATE (Phase 60) — moved to agents/ultron/gate.py (Phase B):
    # NEVER_SUBMIT / PAYOUT_TIER constants + validate_finding().

    def _probe_injection(self, urls: list, max_urls: int = 30, max_params: int = 8,
                         cookie: str = "", headers: dict = None) -> list:
        """Lightweight injection smell-test over crawled URLs that carry query params.

        For each param sends ONE benign probe — a single quote (error-based SQLi
        signal) and a reflected marker (XSS) — and flags CANDIDATES, not exploits.
        Minimal-proof by design: one extra request per param, hard-capped, no data
        pulled. Findings carry validated=True (signal observed directly) + evidence
        + repro so the quality gate and report can use them. Authorized targets only.

        cookie / headers carry a logged-in session so authenticated surfaces (most
        real bug-bounty targets) can be probed, not just the public login page.
        """
        import time
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        _hdrs = dict(headers or {})
        if cookie:
            _hdrs["Cookie"] = cookie
        try:
            import requests  # noqa: F401 — availability check; calls go via _http_get
        except Exception:
            return []
        out, seen, tested = [], set(), 0
        for u in urls or []:
            if tested >= max_urls:
                break
            try:
                parts = urlsplit(u)
                qs = parse_qsl(parts.query, keep_blank_values=True)
                if not qs or parts.scheme not in ("http", "https"):
                    continue
                tested += 1
                # baseline response for this URL (once) — for differential detection
                base_status, base_len, base_body = None, None, ""
                try:
                    b = _http_get(u, headers=_hdrs)
                    base_status, base_len, base_body = b.status_code, len(b.text or ""), (b.text or "")
                except Exception:
                    pass
                for i, (k, v) in enumerate(qs[:max_params]):
                    sig = (parts.scheme, parts.netloc, parts.path, k)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    # --- SQLi probe (single quote): error-string OR response anomaly ---
                    try:
                        # seed empty params with "1" — a bare quote on an empty value often
                        # hits a trivial-query short-circuit (no error); a seeded value forces
                        # the quote into the WHERE clause where it breaks. Crawled URLs very
                        # often carry empty params (?q=, ?id=), so this is the common case.
                        q = qs.copy(); q[i] = (k, (v or "1") + "'")
                        purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                        time.sleep(0.1)
                        r = _http_get(purl, headers=_hdrs)
                        body = r.text or ""
                        m = _SQL_ERROR_SIGNS.search(body)
                        # discipline (CBH sqli-canned FP trap): a DB-error string that ALSO
                        # appears in the baseline is a static/canned message, not injection-
                        # triggered — require the error to be DIFFERENTIAL (post-inject only).
                        if m and base_body and _SQL_ERROR_SIGNS.search(base_body):
                            m = None
                        # anomaly: baseline was a healthy 200-with-body, but the quote
                        # flips it to a server error / empty body = query broke (classic SQLi).
                        anomaly = (base_status == 200 and (base_len or 0) > 200
                                   and (r.status_code >= 500 or len(body) == 0))
                        # FP-kill: a 500 caused by a numeric-cast/validation error (int("32'")
                        # -> ValueError) is NOT injection — the param rejects any non-numeric
                        # input, not the quote. Drop the anomaly when the post-inject body carries
                        # a type-error signature the baseline lacks. (DSVW `?size=` dogfood FP.)
                        if (anomaly and _TYPE_ERROR_SIGNS.search(body)
                                and not (base_body and _TYPE_ERROR_SIGNS.search(base_body))):
                            anomaly = False
                        if m:
                            # a real DB-error signature = CONFIRMED error-based SQLi.
                            out.append({
                                "template": "sqli-error-based", "severity": "high",
                                "url": purl, "cve": None, "validated": True,
                                "evidence": f"DB error '{m.group(0)}' surfaced after injecting a single quote into param '{k}'.",
                                "repro": [f"Baseline: GET {u}  -> HTTP {base_status}/{base_len}b",
                                          f"Inject:   GET {purl}",
                                          "Observe the database error in the response body"],
                            })
                            continue
                        elif anomaly:
                            # a quote flipped 200->500/empty but NO DB-error string surfaced. The input
                            # is mishandled, but the CLASS is unconfirmed — a 500 can be SQLi, LFI, XPath,
                            # command-inj, or a parser/cast error. Report as an injection CANDIDATE, not a
                            # CVSS-9.8 SQLi (over-claiming a class off a bare status flip = an invalid report).
                            out.append({
                                "template": "injection-error-anomaly", "severity": "medium",
                                "url": purl, "cve": None, "validated": True,
                                "evidence": (f"Injecting a single quote into param '{k}' changed the response from "
                                             f"HTTP 200/{base_len}b to HTTP {r.status_code}/{len(body)}b, with no DB-error "
                                             f"string. Injection CANDIDATE — class UNCONFIRMED (SQLi / LFI / XPath / "
                                             f"command / parser error); confirm the class manually before reporting."),
                                "repro": [f"Baseline: GET {u}  -> HTTP {base_status}/{base_len}b",
                                          f"Inject:   GET {purl}",
                                          f"Observe the response break to HTTP {r.status_code}/{len(body)}b (class unconfirmed)"],
                            })
                            continue   # one finding per param is enough
                    except Exception:
                        pass
                    # --- reflected-XSS probe (look for unencoded marker) ---
                    try:
                        marker = _XSS_MARKER + "<x>"
                        q = qs.copy(); q[i] = (k, marker)
                        purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                        time.sleep(0.1)
                        r = _http_get(purl, headers=_hdrs)
                        # discipline (xss FP trap): the marker (with angle brackets) reflecting
                        # unencoded only renders as markup in an HTML context. Require the
                        # content-type to be html/xhtml/xml (or absent/unknown — some servers omit
                        # it but serve HTML); a POSITIVE allowlist. This rejects text/plain (e.g. a
                        # 500 error page echoing input — DSVW dogfood FP), application/json,
                        # javascript, css, octet-stream, etc. where the marker can't execute.
                        _ct = ""
                        try:
                            _ct = (r.headers.get("Content-Type") or "").lower()
                        except Exception:
                            _ct = ""
                        _html_ctx = (not _ct) or ("html" in _ct) or ("xml" in _ct)
                        _body_x = r.text or ""
                        _pos = _body_x.find(marker)
                        # context classifier: a reflection only executes if `<x>` can start a NEW
                        # element. Reflections inside a comment / rawtext element (script/title/
                        # textarea) are inert → drop (don't claim what we can't prove). An attribute-
                        # context reflection needs a breakout → report as a lower-confidence candidate.
                        if _pos != -1 and _html_ctx:
                            _ctx = _xss_reflection_ctx(_body_x, marker)
                            if _ctx not in ("comment", "rawtext"):
                                _exec = (_ctx == "html")
                                out.append({
                                    "template": "xss-reflected", "severity": "medium",
                                    "url": purl, "cve": None, "validated": True,
                                    "evidence": (f"Input '{marker}' reflected unencoded in "
                                                 + ("an executable HTML element context (`<x>` introduces a new tag)"
                                                    if _exec else
                                                    "a tag/attribute context (needs a quote/bracket breakout to execute)")
                                                 + f" for param '{k}'."),
                                    "repro": [f"Send: GET {purl}",
                                              f"Find the literal string '{marker}' (angle brackets intact) in the response",
                                              ("Escalate to a script payload (e.g. <svg onload=...>) under authorized manual testing"
                                               if _exec else
                                               "Confirm a quote/bracket breakout from the attribute before escalating")],
                                })
                    except Exception:
                        pass
                    # --- param-name-routed tests (dork-derived): fire only the test the
                    #     param name suggests, so redirect/file params get the right probe ---
                    kl = k.lower()
                    if any(h in kl for h in _PARAM_HINTS["open-redirect"]):
                        try:
                            q = qs.copy(); q[i] = (k, "https://" + _REDIR_MARKER + "/")
                            purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                            time.sleep(0.1)
                            r = _http_get(purl, headers=_hdrs, allow_redirects=False)
                            loc = (r.headers.get("Location") or "") if hasattr(r, "headers") else ""
                            if r.status_code in (301, 302, 303, 307, 308) and _REDIR_MARKER in loc:
                                out.append({
                                    "template": "open-redirect", "severity": "medium",
                                    "url": purl, "cve": None, "validated": True,
                                    "evidence": f"Param '{k}' controls the redirect target — HTTP {r.status_code} "
                                                f"Location: {loc[:80]} points to the attacker host.",
                                    "repro": [f"Send: GET {purl}",
                                              f"Observe the {r.status_code} redirect to {_REDIR_MARKER} in the Location header"],
                                })
                                continue
                        except Exception:
                            pass
                    if any(h in kl for h in _PARAM_HINTS["lfi"]):
                        try:
                            q = qs.copy(); q[i] = (k, _LFI_PROBE)
                            purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q, safe="/."), ""))
                            time.sleep(0.1)
                            r = _http_get(purl, headers=_hdrs)
                            if _LFI_SIGN.search(r.text or ""):
                                out.append({
                                    "template": "lfi-path-traversal", "severity": "high",
                                    "url": purl, "cve": None, "validated": True,
                                    "evidence": f"Param '{k}' is path-traversable — /etc/passwd (or win.ini) signature "
                                                f"in the response.",
                                    "repro": [f"Send: GET {purl}",
                                              "Observe the file contents (root:x:0:0 / [boot loader]) in the response"],
                                })
                                continue
                        except Exception:
                            pass
                    # --- NoSQL operator injection (error-based, clear oracle) ---
                    #     turn  k=v  into  k[$ne]=v  — a Mongo/Couch backend that passes it
                    #     raw often throws a parse error (differential, not in baseline).
                    try:
                        q = [(kk, vv) for kk, vv in qs]
                        q[i] = (k + "[$ne]", v or "1")
                        purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                        time.sleep(0.1)
                        r = _http_get(purl, headers=_hdrs)
                        body = r.text or ""
                        nm = _NOSQL_ERROR_SIGNS.search(body)
                        # differential discipline: a NoSQL-error token already in the baseline
                        # is static text, not injection-triggered — require it to be new.
                        if nm and not (base_body and _NOSQL_ERROR_SIGNS.search(base_body)):
                            out.append({
                                "template": "nosqli-operator", "severity": "high",
                                "url": purl, "cve": None, "validated": True,
                                "evidence": f"Operator injection '{k}[$ne]' surfaced a NoSQL error "
                                            f"('{nm.group(0)}') — the param feeds an unsanitized Mongo/Couch query.",
                                "repro": [f"Baseline: GET {u}",
                                          f"Inject:   GET {purl}",
                                          "Observe the NoSQL parse error; confirm auth-bypass manually with "
                                          "a JSON body {\"user\":{\"$gt\":\"\"},\"pass\":{\"$gt\":\"\"}}"],
                            })
                            continue
                    except Exception:
                        pass
                    # --- command injection (arithmetic-echo oracle: executed != reflected) ---
                    try:
                        hit = False
                        for pay in _CMDI_PAYLOADS:
                            q = qs.copy(); q[i] = (k, (v or "1") + pay)
                            purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                            time.sleep(0.1)
                            r = _http_get(purl, headers=_hdrs)
                            if _CMDI_HIT.search(r.text or ""):
                                out.append({
                                    "template": "command-injection", "severity": "critical",
                                    "url": purl, "cve": None, "validated": True,
                                    "evidence": f"Param '{k}' is command-injectable — the shell evaluated "
                                                f"$((7*7)) to 49 ({_CMDI_MARK}49{_CMDI_MARK} in the response); "
                                                f"a reflection would show the literal expression.",
                                    "repro": [f"Send: GET {purl}",
                                              f"Observe '{_CMDI_MARK}49{_CMDI_MARK}' (the arithmetic was executed, not echoed)",
                                              "Confirm RCE manually with a bounded command (id / whoami) under authorization"],
                                })
                                hit = True
                                break
                        if hit:
                            continue
                    except Exception:
                        pass
                    # --- blind boolean SQLi (stability-gated differential, no error needed) ---
                    #     TRUE must reproduce the baseline, FALSE must clearly differ AND be
                    #     reproducible — a non-deterministic page can't satisfy all three, so
                    #     random length jitter doesn't become a false positive.
                    try:
                        seed = v or "1"
                        def _plen(val):
                            q2 = qs.copy(); q2[i] = (k, seed + val)
                            pu = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q2), ""))
                            time.sleep(0.1)
                            rr = _http_get(pu, headers=_hdrs)
                            return len(rr.text or ""), pu, rr.status_code
                        flagged = False
                        for t_suf, f_suf, ctx in ((" AND 1=1", " AND 1=2", "numeric"),
                                                  ("' AND '1'='1", "' AND '1'='2", "string")):
                            if base_len is None or base_len < 80:
                                break                                # no stable baseline to diff against
                            lt, put, _ = _plen(t_suf)                # TRUE  branch
                            lf, puf, _ = _plen(f_suf)                # FALSE branch
                            # Oracle by EQUALITY, not delta: TRUE must reproduce the baseline tightly
                            # (<=2b) and FALSE must DIFFER yet be exactly reproducible. A boolean diff
                            # can be tiny (DVWA blind = 6 bytes: "exists" vs "MISSING") — a delta margin
                            # misses it. The strict-equality gates also make dynamic/jittery pages
                            # self-exclude (TRUE won't match baseline, FALSE won't be stable) = no FP.
                            true_matches = abs(lt - base_len) <= 2
                            false_differs = lf != lt
                            if true_matches and false_differs:
                                lf2, _, _ = _plen(f_suf)             # FALSE must be byte-stable on re-test
                                if lf == lf2:
                                    out.append({
                                        "template": "sqli-blind-boolean", "severity": "high",
                                        "url": put, "cve": None, "validated": True,
                                        "evidence": f"Param '{k}' is boolean-blind SQLi-able ({ctx} context): "
                                                    f"'{t_suf.strip()}' reproduces the baseline ({base_len}b == {lt}b) "
                                                    f"while '{f_suf.strip()}' changes it to {lf}b (stable on re-test {lf2}b) "
                                                    f"— the condition controls the query result.",
                                        "repro": [f"TRUE : GET {put}  -> {lt}b (== baseline {base_len}b)",
                                                  f"FALSE: GET {puf}  -> {lf}b (reproducible {lf2}b)",
                                                  "Extract data with sqlmap --technique=B, or a CASE/SUBSTRING oracle"],
                                    })
                                    flagged = True
                                    break
                        if flagged:
                            continue
                    except Exception:
                        pass
                    # --- SSTI (unique-arithmetic oracle: evaluated 1787569, not reflected) ---
                    try:
                        hit = False
                        for pay in _SSTI_PAYLOADS:
                            q = qs.copy(); q[i] = (k, pay)
                            purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                            time.sleep(0.1)
                            r = _http_get(purl, headers=_hdrs)
                            body = r.text or ""
                            # evaluated (1787569 present) AND the literal expression is NOT echoed back
                            if _SSTI_HIT.search(body) and "1337*1337" not in body and "1787569" not in base_body:
                                out.append({
                                    "template": "ssti", "severity": "high",
                                    "url": purl, "cve": None, "validated": True,
                                    "evidence": f"Param '{k}' is template-injectable — the engine evaluated "
                                                f"{pay} to 1787569 (a reflection would echo the literal expression).",
                                    "repro": [f"Send: GET {purl}",
                                              "Observe 1787569 in the response (1337*1337 was executed server-side)",
                                              "Identify the engine and escalate to RCE per the engine's sandbox-escape"],
                                })
                                hit = True; break
                        if hit:
                            continue
                    except Exception:
                        pass
                    # --- time-based blind SQLi (double-sampled to defeat jitter) ---
                    #     only on the first 2 params/URL (each probe costs ~5s) and only if
                    #     the baseline itself was fast — require BOTH the inject AND a confirm
                    #     to exceed the threshold, while a benign control stays fast = no FP.
                    if i < 2 and base_status is not None:
                        try:
                            seed = v or "1"
                            def _elapsed(val):
                                q3 = qs.copy(); q3[i] = (k, seed + val)
                                pu = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q3), ""))
                                t0 = time.time()
                                try:
                                    _http_get(pu, headers=_hdrs, timeout=12)
                                except Exception:
                                    pass                   # use REAL elapsed below: a real SLEEP that
                                # exceeds the timeout still reads ~12s (>= threshold = flagged), but a
                                # FAST connection error (refused/reset, ~0s) reads small and is NOT
                                # mistaken for a delay — kills the flaky-endpoint false positive.
                                return time.time() - t0, pu
                            # baseline timing for THIS param (benign control must be fast)
                            ctrl, _ = _elapsed(" AND 1=1-- -")
                            if ctrl < 2.0:
                                for tp in _SQLI_TIME:
                                    el, pu = _elapsed(tp)
                                    if el >= 4.5:
                                        el2, _ = _elapsed(tp)           # confirm — jitter won't repeat
                                        if el2 >= 4.5:
                                            out.append({
                                                "template": "sqli-blind-time", "severity": "high",
                                                "url": pu, "cve": None, "validated": True,
                                                "evidence": f"Param '{k}' is time-blind SQLi-able: '{tp}' delayed the "
                                                            f"response to {el:.1f}s (confirm {el2:.1f}s) while a benign "
                                                            f"control returned in {ctrl:.1f}s — the injected SLEEP executed.",
                                                "repro": [f"Control: GET ...{k}={seed} AND 1=1  -> {ctrl:.1f}s",
                                                          f"Inject : GET {pu}  -> {el:.1f}s (re-test {el2:.1f}s)",
                                                          "Extract with sqlmap --technique=T"],
                                            })
                                            break
                        except Exception:
                            pass
                # --- Host-header injection (per-URL, reflection oracle) ---
                #     inject a marker host via X-Forwarded-Host; if it lands in a redirect
                #     Location (or the body), the app trusts the header = cache/reset poisoning.
                try:
                    hh = dict(_hdrs)
                    hh["X-Forwarded-Host"] = _HHI_MARKER
                    hh["X-Forwarded-Server"] = _HHI_MARKER
                    time.sleep(0.1)
                    r = _http_get(u, headers=hh, allow_redirects=False)
                    loc = (r.headers.get("Location") or "") if hasattr(r, "headers") else ""
                    if _HHI_MARKER in loc or (base_body and _HHI_MARKER in (r.text or "")
                                              and _HHI_MARKER not in base_body):
                        where = "Location header" if _HHI_MARKER in loc else "response body"
                        out.append({
                            "template": "host-header-injection", "severity": "medium",
                            "url": u, "cve": None, "validated": True,
                            "evidence": f"X-Forwarded-Host: {_HHI_MARKER} is reflected in the {where} — "
                                        f"the app trusts a client-controlled host (password-reset / cache poisoning).",
                            "repro": [f"Send: GET {u}  with header  X-Forwarded-Host: {_HHI_MARKER}",
                                      f"Observe {_HHI_MARKER} reflected in the {where}"],
                        })
                except Exception:
                    pass
            except Exception:
                continue
        if out:
            print(f"[ULTRON] injection smell-test flagged {len(out)} candidate(s) "
                  f"across {tested} parameterized endpoint(s).")
        return out

    def _probe_path_params(self, urls: list, max_urls: int = 20, cookie: str = "",
                           headers: dict = None) -> list:
        """Inject into the LAST id-looking PATH segment (/api/user/1 -> /api/user/1') —
        the GET-query probe only tests ?params, but REST APIs put the object id in the path
        (BOLA / path SQLi). Differential DB/NoSQL error vs baseline = injectable path param.
        Authorized targets only."""
        import time
        from urllib.parse import urlsplit, urlunsplit, quote
        _hdrs = dict(headers or {})
        if cookie:
            _hdrs["Cookie"] = cookie
        try:
            import requests  # noqa: F401
        except Exception:
            return []
        out, seen, tested = [], set(), 0
        for u in urls or []:
            if tested >= max_urls:
                break
            try:
                parts = urlsplit(u)
                if parts.query or parts.scheme not in ("http", "https"):
                    continue                                  # query URLs are the other probe's job
                segs = [s for s in parts.path.split("/") if s]
                if not segs:
                    continue
                last = segs[-1]
                # only id-looking segments (numeric, or short hex/uuid-ish) — avoid /about, /login
                if not re.match(r"^[0-9]+$|^[0-9a-fA-F]{6,}$|^[0-9a-f-]{8,}$", last):
                    continue
                sig = (parts.netloc, "/".join(segs[:-1]))
                if sig in seen:
                    continue
                seen.add(sig); tested += 1
                base = _http_get(u, headers=_hdrs)
                base_body = base.text or ""
                if _SQL_ERROR_SIGNS.search(base_body) or _NOSQL_ERROR_SIGNS.search(base_body):
                    continue                                  # noisy baseline — can't be differential
                inj_path = "/" + "/".join(segs[:-1] + [quote(last + "'", safe="")])
                purl = urlunsplit((parts.scheme, parts.netloc, inj_path, "", ""))
                time.sleep(0.1)
                r = _http_get(purl, headers=_hdrs)
                body = r.text or ""
                m = _SQL_ERROR_SIGNS.search(body) or _NOSQL_ERROR_SIGNS.search(body)
                if m:
                    out.append({
                        "template": "sqli-error-based", "severity": "high",
                        "url": purl, "cve": None, "validated": True,
                        "evidence": f"Path segment '{last}' is injectable — a single quote surfaced a DB error "
                                    f"('{m.group(0)}') absent from the baseline. REST path-param SQLi/BOLA.",
                        "repro": [f"Baseline: GET {u}",
                                  f"Inject:   GET {purl}",
                                  "Observe the database error; confirm with sqlmap -u with a * at the path id"],
                    })
            except Exception:
                continue
        if out:
            print(f"[ULTRON] path-param probe flagged {len(out)} candidate(s).")
        return out

    def _probe_stored_xss(self, urls: list, max_urls: int = 15, cookie: str = "",
                          headers: dict = None) -> list:
        """Two-step stored XSS: inject a unique marker (with brackets) into each param, then
        re-fetch the OTHER crawled pages — if the marker comes back UNENCODED on a different
        page, the input was stored and rendered as markup. Requiring a DIFFERENT page (not the
        inject URL) avoids counting plain reflection. Authorized targets only."""
        import time
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        _hdrs = dict(headers or {})
        if cookie:
            _hdrs["Cookie"] = cookie
        try:
            import requests  # noqa: F401
        except Exception:
            return []
        cand = [u for u in (urls or []) if urlsplit(u).scheme in ("http", "https")][:max_urls]
        views = cand
        # Pass 1: inject a GLOBALLY-UNIQUE marker per (url,param) — a per-URL idx collides across
        # URLs (url-A's stored marker then mis-attributes to url-B), so use a running counter.
        planted, n = {}, 0
        for u in cand:
            try:
                parts = urlsplit(u)
                qs = parse_qsl(parts.query, keep_blank_values=True)
                if not qs:
                    continue
                for idx, (k, v) in enumerate(qs[:4]):
                    mark = f"{_STORED_MARK}{n}<x>"; n += 1
                    q = qs.copy(); q[idx] = (k, mark)
                    iurl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                    time.sleep(0.1)
                    try:
                        _http_get(iurl, headers=_hdrs)
                    except Exception:
                        continue
                    planted[mark] = {"src": u.split("?")[0], "param": k, "iurl": iurl}
            except Exception:
                continue
        # Pass 2: fetch each view ONCE (was N*M*N requests — now N injects + N views), flag a
        # marker that surfaces UNENCODED on a DIFFERENT page than where it was injected (= stored).
        out = []
        for vu in views:
            try:
                body = _http_get(vu, headers=_hdrs).text or ""
            except Exception:
                continue
            vbase = vu.split("?")[0]
            for mark, info in planted.items():
                if mark in body and info["src"] != vbase:
                    out.append({
                        "template": "xss-stored", "severity": "high",
                        "url": vu, "cve": None, "validated": True,
                        "evidence": f"Marker injected via {info['param']} at {info['src']} appeared UNENCODED "
                                    f"at {vu} — input is stored and rendered as markup on another page.",
                        "repro": [f"Step 1: GET {info['iurl']}",
                                  f"Step 2: GET {vu}  -> find '{mark}' (brackets intact)",
                                  "Escalate to <script>/<img onerror> under authorization"],
                    })
                    break
        if out:
            print(f"[ULTRON] stored-XSS probe flagged {len(out)} candidate(s).")
        return out

    def _probe_post(self, endpoints: list, max_eps: int = 15, max_fields: int = 8,
                    cookie: str = "", headers: dict = None) -> list:
        """Inject into POST/PUT JSON or form bodies captured by spa_crawl — the auth /
        mutation endpoints (login, search, GraphQL) the GET probe can't reach. This is
        where the high-value bugs live (NoSQL auth-bypass is POST-JSON only).

        Per string field, replays the request with ONE mutated field, using the SAME
        clean oracles as the GET probe:
          - SQLi      : append `'`  -> a DIFFERENTIAL DB error (not present in baseline)
          - cmd-inj   : `;echo jvz9c$((7*7))jvz9c` -> EXECUTED marker (can't be reflected)
          - NoSQL     : value -> {"$ne": null} (JSON) -> auth-bypass status flip / Mongo error
        Authorized targets only. cookie/headers carry the logged-in session.
        """
        import json as _json
        from urllib.parse import parse_qsl
        _hdrs = dict(headers or {})
        if cookie:
            _hdrs["Cookie"] = cookie
        try:
            import requests  # noqa: F401 — availability check; calls go via _http_post
        except Exception:
            return []
        out, tested = [], 0
        for ep in endpoints or []:
            if tested >= max_eps:
                break
            url = ep.get("url") or ""
            body = ep.get("body") or ""
            ctype = (ep.get("ctype") or "").lower()
            # --- XXE: XML body -> inject a file-read external entity, look for /etc/passwd ---
            if "xml" in ctype or body.lstrip().startswith("<?xml") or body.lstrip().startswith("<"):
                try:
                    tested += 1
                    base = _http_post(url, data=body.encode("utf-8") if isinstance(body, str) else body,
                                      headers={**_hdrs, "Content-Type": ctype or "application/xml"})
                    base_body = base.text or ""
                    if not _LFI_SIGN.search(base_body):       # only if the file sig isn't already there
                        dt = ('<?xml version="1.0"?>\n<!DOCTYPE jvzx [<!ENTITY xxe SYSTEM '
                              '"file:///etc/passwd">]>\n')
                        # wrap the original root element's first text node value with &xxe;
                        inj = dt + re.sub(r">[^<]*<", ">&xxe;<", body, count=1) if "<" in body else dt + "<x>&xxe;</x>"
                        r = _http_post(url, data=inj.encode("utf-8"),
                                       headers={**_hdrs, "Content-Type": ctype or "application/xml"})
                        if _LFI_SIGN.search(r.text or ""):
                            out.append({
                                "template": "xxe", "severity": "high",
                                "url": url, "cve": None, "validated": True,
                                "evidence": f"XML endpoint {url} resolves external entities — injecting a "
                                            f"file:///etc/passwd SYSTEM entity returned the file (root:x signature).",
                                "repro": [f"POST {url} with a DOCTYPE defining "
                                          f'<!ENTITY xxe SYSTEM "file:///etc/passwd"> and &xxe; in the body',
                                          "Observe /etc/passwd contents; pivot to SSRF / OOB exfil"],
                            })
                except Exception:
                    pass
                continue
            # parse the body into a flat {field: value} dict (JSON object or form-encoded)
            fields, mode = None, None
            if "json" in ctype or body.strip().startswith("{"):
                try:
                    obj = _json.loads(body)
                    if isinstance(obj, dict):
                        fields, mode = obj, "json"
                except Exception:
                    pass
            if fields is None:
                try:
                    pairs = parse_qsl(body, keep_blank_values=True)
                    if pairs:
                        fields, mode = dict(pairs), "form"
                except Exception:
                    pass
            if not fields:
                continue
            keys = [k for k, v in fields.items()
                    if isinstance(v, (str, int, float, type(None)))][:max_fields]
            if not keys:
                continue
            tested += 1

            def _send(mut):
                if mode == "json":
                    return _http_post(url, json_body=mut, headers=_hdrs)
                return _http_post(url, data={k: ("" if v is None else v) for k, v in mut.items()},
                                  headers=_hdrs)
            try:
                b = _send(fields)
                base_status, base_body = b.status_code, (b.text or "")
            except Exception:
                continue
            base_err = bool(_SQL_ERROR_SIGNS.search(base_body) or _NOSQL_ERROR_SIGNS.search(base_body))

            flagged = False
            for k in keys:
                if flagged:
                    break
                sval = "" if fields.get(k) is None else str(fields.get(k))
                # --- error-based SQLi / NoSQL (differential) ---
                try:
                    m = dict(fields); m[k] = (sval or "1") + "'"
                    r = _send(m); rb = r.text or ""
                    hit = _SQL_ERROR_SIGNS.search(rb) or _NOSQL_ERROR_SIGNS.search(rb)
                    if hit and not base_err:
                        out.append({
                            "template": "sqli-error-based", "severity": "high",
                            "url": url, "cve": None, "validated": True,
                            "evidence": f"POST field '{k}' on {url}: a single quote surfaced a DB error "
                                        f"('{hit.group(0)}') absent from the baseline = server-side query injection.",
                            "repro": [f"POST {url}  with {mode} field {k}={sval or '1'}'",
                                      "Observe the database error in the response; confirm with sqlmap"],
                        })
                        flagged = True; continue
                except Exception:
                    pass
                # --- command injection (executed arithmetic, not reflected) ---
                try:
                    m = dict(fields); m[k] = sval + ";echo " + _CMDI_MARK + "$((7*7))" + _CMDI_MARK
                    r = _send(m)
                    if _CMDI_HIT.search(r.text or ""):
                        out.append({
                            "template": "command-injection", "severity": "critical",
                            "url": url, "cve": None, "validated": True,
                            "evidence": f"POST field '{k}' on {url}: the shell evaluated $((7*7)) to 49 "
                                        f"({_CMDI_MARK}49{_CMDI_MARK}) — command injection, not reflection.",
                            "repro": [f"POST {url}  with {mode} field {k} appended ;echo {_CMDI_MARK}$((7*7)){_CMDI_MARK}",
                                      f"Observe '{_CMDI_MARK}49{_CMDI_MARK}'; confirm RCE with id/whoami under authorization"],
                        })
                        flagged = True; continue
                except Exception:
                    pass
                # --- NoSQL operator auth-bypass (JSON bodies only) ---
                if mode == "json":
                    try:
                        m = dict(fields); m[k] = {"$ne": None}
                        r = _send(m); rb = r.text or ""
                        nerr = _NOSQL_ERROR_SIGNS.search(rb)
                        # oracle: a 4xx baseline (auth fail) flipping to 2xx with the operator, OR a
                        # NoSQL parse error = the field feeds an unsanitized query (auth-bypass candidate).
                        flip = base_status >= 400 and r.status_code < 300
                        if (flip or nerr) and not base_err:
                            why = (f"NoSQL error '{nerr.group(0)}'" if nerr
                                   else f"status flipped {base_status} -> {r.status_code} with operator injection")
                            out.append({
                                "template": "nosqli-operator", "severity": "critical",
                                "url": url, "cve": None, "validated": True,
                                "evidence": f"POST field '{k}' on {url}: {{\"$ne\":null}} — {why}. The field is "
                                            f"placed into a Mongo/Couch query unsanitized (auth-bypass candidate).",
                                "repro": [f'POST {url}  with JSON {{"{k}":{{"$ne":null}}, ...}}',
                                          "If you got a session/token, you bypassed auth as the first matching user"],
                            })
                            flagged = True; continue
                    except Exception:
                        pass
        if out:
            print(f"[ULTRON] POST-body probe flagged {len(out)} candidate(s) across {tested} endpoint(s).")
        return out

    def _validate_finding(self, f: dict, exploits_map: dict) -> dict:
        return gate.validate_finding(f, exploits_map,
                                     _load_roe().get("out_of_scope_types", []))

    def _write_evidence_bundle(self, folder: str, target: str, reportable: list) -> int:
        return evidence_bundle.write_bundle(folder, target, reportable)

    def _format_bb_report(self, target, findings, exploits_map, pipeline_data, validated):
        return report.format_bb_report(target, findings, exploits_map, pipeline_data, validated)

    def _build_test_plan(self, target: str, findings: list, pipeline_data: dict) -> list:
        return report.build_test_plan(target, findings, pipeline_data)

    def _impact_line(self, f: dict) -> str:
        return report.impact_line(f)

    def bug_bounty(self, target: str, validate: bool = True, force: bool = False,
                   cookie: str = "", owner: str = "", attacker: str = "", discover: bool = False) -> dict:
        """Full bug-bounty hunt: recon pipeline -> parse findings -> CVE/exploit
        lookup -> (validate) -> structured PoC report. Authorized targets only.
        cookie carries a logged-in session so the crawl + injection probe cover
        authenticated surface (most real targets), not just the public pages."""
        if not target:
            return {"success": False, "message": "Target missing. Usage: 'bug bounty example.com'", "data": {}}

        # clean target (strip scheme)
        target = re.sub(r"^https?://", "", target.strip(), flags=re.IGNORECASE).rstrip("/")
        print(f"[ULTRON] Bug-bounty workflow on {target}")
        _sc = _scope_check(target)
        if _sc:
            print(f"[ULTRON][SCOPE] {_sc}")
        _scope = _in_scope(target)
        if _scope == "out" and not force:
            return {"success": False, "data": {"target": target},
                    "message": f"REFUSED: '{target}' is OUT OF SCOPE per data/scope.json. "
                               f"Pass force=True (or --force) only if you're certain it's authorized."}
        # PORTED FROM JARVIS S18 (dogfood): refuse unknown-scope too -> was multi-minute hang.
        if _scope == "unknown" and not force:
            return {"success": False, "data": {"target": target, "scope": "unknown"},
                    "message": f"REFUSED: '{target}' is NOT in data/scope.json. Won't auto-run an "
                               f"active scan against an unconfirmed target. Either add it to scope "
                               f"(`scope add {target}`) or pass force=True (--force) to override."}

        # ── F4: execution timeline (immutable recorder; degrades silently) ──
        try:
            from core import timeline as _timeline
            _tl = _timeline.start_run(target)
        except Exception:
            _tl = None

        def _tl_event(step, **kw):
            if _tl:
                try:
                    _tl.record_event(step, **kw)
                except Exception:
                    pass

        # ── Stage 1: Recon pipeline (nmap->subfinder->httpx->nuclei->katana) ──
        pipeline = self.full_pipeline(target, cookie=cookie, discover=discover)
        pdata = pipeline.get("data", {})
        nuclei_raw = pdata.get("sections", {}).get("nuclei", "")
        _recon_art = []
        if _tl:
            for _n, _d in (("endpoints.json", pdata.get("urls", [])),
                           ("post_endpoints.json", pdata.get("post_endpoints", []))):
                _a = _tl.write_artifact(_n, _d)
                if _a and _d:
                    _recon_art.append(_a)
        _tl_event("recon", tool="full_pipeline",
                  inputs={"target": target, "cookie": bool(cookie)},
                  outputs={"urls": len(pdata.get("urls", [])),
                           "post_endpoints": len(pdata.get("post_endpoints", []))},
                  artifacts=_recon_art,
                  status="ok" if pipeline.get("success") else "failed")

        # ── Stage 2: Parse nuclei -> structured findings ──
        findings = _parse_nuclei_findings(nuclei_raw)

        # ── Stage 2.5: Injection smell-test on crawled parameterized endpoints ──
        # nuclei detects known CVEs/misconfigs, not custom app-logic SQLi/XSS — so
        # actively probe the params katana found and surface injectable candidates.
        try:
            findings += self._probe_injection(pdata.get("urls", []), cookie=cookie)
        except Exception as e:
            print(f"[ULTRON] injection probe skipped: {e}")
        # POST-body probe on the auth/mutation endpoints spa_crawl captured (NoSQL auth-
        # bypass, POST SQLi/cmd-inj live here — the GET probe can't reach them).
        try:
            findings += self._probe_post(pdata.get("post_endpoints", []), cookie=cookie)
        except Exception as e:
            print(f"[ULTRON] POST probe skipped: {e}")
        # path-param injection (REST /api/user/{id}) + stored-XSS 2-step over crawled pages
        try:
            findings += self._probe_path_params(pdata.get("urls", []), cookie=cookie)
        except Exception as e:
            print(f"[ULTRON] path-param probe skipped: {e}")
        try:
            findings += self._probe_stored_xss(pdata.get("urls", []), cookie=cookie)
        except Exception as e:
            print(f"[ULTRON] stored-XSS probe skipped: {e}")
        _tl_event("probe", tool="injection/post/path/stored-xss",
                  outputs={"findings": len(findings)})

        # ── Stage 2.6: Multi-user authz (IDOR/BOLA oracle B3) — only when 2 principals exist ──
        # The single-session probes above can't reach IDOR (the top real-bounty class). If the
        # user set 2 sessions, replay every id-bearing crawled URL as owner-vs-attacker-vs-anon.
        try:
            from core import session_manager as sm, request_mutator as rm
            _names = list(sm.list_sessions().keys())
            _owner = owner or (_names[0] if len(_names) >= 2 else "")
            _attacker = attacker or next((n for n in _names if n != _owner), "")
            if _owner and _attacker and sm.headers_for(_owner) and sm.headers_for(_attacker):
                # id-bearing URLs only (mutate_url returns variants iff a swappable id exists)
                _cands = [u for u in dict.fromkeys(pdata.get("urls", [])) if rm.mutate_url(u)][:15]
                print(f"[ULTRON] Stage 2.6: IDOR oracle on {len(_cands)} id-bearing URL(s) "
                      f"({_owner} vs {_attacker})")
                for _u in _cands:
                    try:
                        _r = self.idor_check(_u, owner=_owner, attacker=_attacker)
                        findings += _r.get("data", {}).get("findings", [])
                    except Exception:
                        continue
            elif _names:
                print(f"[ULTRON] Stage 2.6 skipped: need 2 sessions for IDOR (have {len(_names)}). "
                      f"Set them: session set userA cookie ..")
        except Exception as e:
            print(f"[ULTRON] IDOR oracle skipped: {e}")
        _tl_event("idor", tool="idor_check", outputs={"findings": len(findings)})

        # ── Stage 3: CVE -> exploit lookup (critical/high only, capped) ──
        exploits_map = {}
        cve_findings = [f for f in findings if f["cve"] and f["severity"] in ("critical", "high")]
        for f in cve_findings[:5]:
            try:
                ex = self.find_exploits(f["cve"])
                pocs = ex.get("data", {}).get("pocs", [])
                if pocs:
                    top = pocs[0]
                    exploits_map[f["cve"]] = top.get("url", "") + f" ({ex['data'].get('total', len(pocs))} found)"
            except Exception as e:
                print(f"[ULTRON] exploit lookup failed for {f['cve']}: {e}")
        _tl_event("cve", tool="find_exploits", outputs={"exploits": len(exploits_map)})

        # ── Stage 4: Validate (re-probe flagged URLs to cut false positives) ──
        validated = False
        if validate and findings:
            flagged_urls = list({f["url"] for f in findings[:8] if f["url"]})
            if flagged_urls:
                try:
                    probe = self.httpx_probe(" ".join(flagged_urls[:5]))
                    live = probe.get("message", "")
                    for f in findings:
                        if f["url"]:
                            f["validated"] = f["url"].split("//")[-1].split("/")[0] in live
                    validated = True
                except Exception as e:
                    print(f"[ULTRON] validate stage skipped: {e}")
        _tl_event("validate", tool="httpx_probe",
                  outputs={"validated": sum(1 for f in findings if f.get("validated"))},
                  status="ok" if validated else "skipped")

        # ── Stage 4.5: Quality gate — score each finding, drop noise/weak ones ──
        for f in findings:
            f["_gate"] = self._validate_finding(f, exploits_map)
        reportable = [f for f in findings if f["_gate"]["report"]]
        filtered = len(findings) - len(reportable)
        _gate_art = []
        if _tl:
            _a = _tl.write_artifact("findings.json", findings)
            if _a and findings:
                _gate_art.append(_a)
        _tl_event("gate", tool="_validate_finding",
                  outputs={"reportable": len(reportable), "filtered": filtered},
                  artifacts=_gate_art)

        # ── Auto-capture: a confirmed finding promotes its technique in the playbook
        #     (novelty-checked; a reference technique that fires on a real target
        #     gets marked PROVEN). Every hunt feeds the edge. ──
        try:
            from core import playbook as pb
            _db = report.detect_db(pdata.get("sections", {}).get("httpx", "") or "", findings)
            _stack = "" if _db == "generic" else _db
            _CAP = {
              "sqli-error-based": ("sqli", "error/anomaly SQLi: a single quote (seed empty params with 1') breaks the query", "param=1'"),
              "xss-reflected": ("xss-reflected", "reflected XSS: marker echoed unencoded in the response", "param=jvz9xqk7z<x>"),
              "open-redirect": ("open-redirect", "param controls the redirect target", "param=//attacker.example"),
              "lfi-path-traversal": ("lfi", "path traversal reads /etc/passwd", "param=../../../../etc/passwd"),
            }
            for f in reportable:
                c = _CAP.get(f.get("template"))
                if c:
                    pb.add(c[0], c[1], stack=_stack, payload=c[2],
                           tell=(f.get("evidence", "") or "")[:90], source="hunt", validated=True)
        except Exception:
            pass

        # ── Stage 5: Structured PoC report ──
        report = self._format_bb_report(target, findings, exploits_map, pdata, validated)
        saved = self.save_report(f"bugbounty_{target}", report)

        # ── Stage 5.5 (F3): canonical Evidence Object (json + submission md) per gate-passed finding ──
        _bundles = 0
        try:
            _folder = os.path.dirname(saved) if saved else None
            if _folder:
                _bundles = self._write_evidence_bundle(_folder, target,
                                            [f for f in findings if f.get("_gate", {}).get("report")])
        except Exception as _e:
            print(f"[ultron] evidence bundle skipped: {_e}")
        _tl_event("evidence", tool="evidence.build",
                  outputs={"bundles": _bundles},
                  artifacts=[{"name": os.path.basename(saved), "path": saved, "kind": "report"}] if saved else [])

        # Phase 63 — remember this target across hunts
        try:
            from core import target_profiles
            target_profiles.record_scan(target, "bug_bounty",
                                        f"{len(reportable)} reportable, {filtered} filtered")
            target_profiles.record_findings(target, reportable)
            if pdata.get("urls"):
                target_profiles.record_endpoints(target, pdata["urls"])
            # Phase 64 — auto-capture evidence for top reportable findings (retest)
            for f in reportable[:3]:
                if f.get("url"):
                    try:
                        self.collect_evidence(f["url"], f.get("template", ""))
                    except Exception:
                        pass
        except Exception as e:
            print(f"[ULTRON] profile update skipped: {e}")

        crit = sum(1 for f in reportable if f["severity"] == "critical")
        high = sum(1 for f in reportable if f["severity"] == "high")
        voice = (
            f"Bug bounty hunt complete on {target}. "
            f"{len(reportable)} report-worthy finding{'s' if len(reportable) != 1 else ''} "
            f"({crit} critical, {high} high) after the quality gate filtered "
            f"{filtered} noise/unconfirmed item{'s' if filtered != 1 else ''}. "
            f"{len(exploits_map)} with known exploits. "
            f"{('Report saved: ' + saved) if saved else 'Report generation failed.'}"
        )

        _run_id = None
        if _tl:
            try:
                _tl.finish()
                _run_id = _tl.run_id
            except Exception:
                pass

        return {
            "success": True,
            "message": voice,
            "data": {
                "target": target,
                "findings": findings,
                "exploits": exploits_map,
                "validated": validated,
                "report": report,
                "saved_path": saved,
                "run_id": _run_id,
            }
        }

    # =====================================
    # FULL RECON WORKFLOW
    # =====================================
    def full_recon(self, target: str, force: bool = False, discover: bool = False) -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Full recon: {target}")
        _sc = _scope_check(target)
        if _sc:
            print(f"[ULTRON][SCOPE] {_sc}")
        _scope = _in_scope(target)
        if _scope == "out" and not force:
            return {"success": False, "data": {"target": target},
                    "message": f"REFUSED: '{target}' is OUT OF SCOPE per data/scope.json. Pass --force if authorized."}
        if _scope == "unknown" and not force:
            return {"success": False, "data": {"target": target, "scope": "unknown"},
                    "message": f"REFUSED: '{target}' is NOT in data/scope.json. Won't auto-run active "
                               f"recon against an unconfirmed target. `scope add {target}` or --force."}

        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        sections = {}

        # ── Nmap ──
        print("[ULTRON] Running Nmap...")
        nmap_result = self.nmap_scan(target, "basic")
        sections["nmap"] = nmap_result.get("message", "Failed.")

        # ── Subfinder ──
        print("[ULTRON] Running Subfinder...")
        sub_result = self.subfinder(target)
        sections["subfinder"] = sub_result.get("message", "Failed.")

        # ── Httpx ── (resolve http/https instead of forcing https)
        print("[ULTRON] Running Httpx...")
        base_url = _resolve_scheme(target)
        httpx_result = self.httpx_probe(base_url)
        sections["httpx"] = httpx_result.get("message", "Failed.")

        # ── Nuclei ──
        print("[ULTRON] Running Nuclei...")
        nuclei_result = self.nuclei_scan(base_url)
        sections["nuclei"] = nuclei_result.get("message", "Failed.")

        # ── Sitemap discovery (PASSIVE, always-on) + content discovery (OPT-IN) ──
        try:
            _sm = _sitemap_paths(base_url)
            sections["sitemap"] = (f"{len(_sm)} page(s) from sitemap.xml / robots.txt:\n"
                                   + "\n".join(_sm[:40]) + (f"\n...and {len(_sm) - 40} more" if len(_sm) > 40 else "")
                                   ) if _sm else "No sitemap.xml / robots.txt paths found."
        except Exception as e:
            sections["sitemap"] = f"Sitemap discovery skipped: {e}"
        if discover:
            print("[ULTRON] Content discovery (opt-in): ffuf/gobuster...")
            try:
                sections["discovery"] = self.content_discovery(target).get("message", "no output")
            except Exception as e:
                sections["discovery"] = f"Content discovery skipped: {e}"
        else:
            sections["discovery"] = "Skipped (opt-in — pass --discover to run ffuf/gobuster)."

        # Reachability gate: if httpx got NO response, the target wasn't actually
        # assessed — empty nuclei/nmap then mean TOOL FAILURE, not a clean target.
        reachable = bool(httpx_result.get("data", {}).get("raw", "").strip())

        # ── LLM Analysis ──
        print("[ULTRON] Analyzing with LLM...")

        context = f"""Target: {target}

=== NMAP PORT SCAN ===
{sections['nmap'][:1500]}

=== SUBDOMAINS (Subfinder) ===
{sections['subfinder'][:800]}

=== HTTP PROBE (Httpx) ===
{sections['httpx'][:500]}

=== VULNERABILITY SCAN (Nuclei) ===
{sections['nuclei'][:1500]}
"""

        prompt = f"""You are Ultron, a cybersecurity analysis AI. Analyze these recon results and write a security assessment report.

{context}

Write a structured report with:
1. Target Overview
2. Open Ports & Services
3. Subdomains Found
4. HTTP/HTTPS Analysis
5. Vulnerabilities Detected
6. Risk Assessment (Low/Medium/High/Critical)
7. Recommendations

Be technical, precise, and actionable. No markdown headers with #. Plain section labels.

{_ANALYST_DISCIPLINE}
{"" if reachable else '''
CRITICAL — SCAN INCONCLUSIVE: the HTTP probe returned NO response, so the target could
not be reached or assessed from this host. Treat every empty result above as TOOL FAILURE,
NOT evidence of safety. You MUST set Risk Assessment to "Inconclusive - target unreachable"
and recommend re-running from a network with egress to the target. Do NOT rate it Low risk.'''}
Report:"""

        analysis = ask_llm(prompt, agent="ultron")
        analysis = _critic_refine(prompt, analysis, agent="ultron")  # Phase 57 (gated)

        # ── Build full report ──
        banner = "" if reachable else (
            "> **SCAN INCONCLUSIVE — target unreachable from scan host.** Empty results below "
            "mean the scanners could not connect, NOT that the target is secure. Re-run from a "
            "network with egress to the target.\n\n")
        full_report = f"""# Ultron Security Report: {target}

{banner}**Target:** {target}
**Generated:** {date_str}

---

## RAW SCAN DATA

### Nmap
{sections['nmap']}

### Subfinder
{sections['subfinder']}

### Httpx
{sections['httpx']}

### Nuclei
{sections['nuclei']}

### Sitemap / robots.txt
{sections.get('sitemap', 'n/a')}

### Content Discovery (ffuf/gobuster)
{sections.get('discovery', 'n/a')}

---

## ANALYSIS

{analysis or 'LLM analysis unavailable.'}

---
*Generated by JARVIS Ultron Security Agent*
"""

        saved_path = self.save_report(target, full_report)
        save_msg = f"Report saved: {saved_path}" if saved_path else "Could not save report."

        prefix = "" if reachable else "[INCONCLUSIVE - target unreachable] "
        summary = prefix + (analysis or sections["nmap"])[:400] + "..."

        return {
            "success": True,
            "message": f"{summary}\n\n{save_msg}",
            "data": {
                "target": target,
                "sections": sections,
                "saved_path": saved_path,
                "full_report": full_report
            }
        }

    # =====================================
    # SYSTEM HEALTH
    # =====================================
    def system_health(self) -> dict:
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory().percent
            issues = []

            if cpu > 90:
                issues.append("High CPU usage")
            if ram > 90:
                issues.append("High RAM usage")

            message = "System health normal." if not issues else "Warnings:\n" + "\n".join(issues)

            return {
                "success": True,
                "message": message,
                "data": {"cpu_usage": cpu, "ram_usage": ram, "issues": issues}
            }
        except Exception as e:
            return {"success": False, "message": str(e), "data": {}}

    # =====================================
    # DEFENSIVE / BLUE-TEAM MODE (host monitor)
    # =====================================
    _DEFENSE_BASELINE = "data/defense_baseline.json"
    # ports & process-name fragments that are classic backdoor / attacker tooling
    _SUSPECT_PORTS = {4444, 4445, 1337, 31337, 5555, 6666, 12345, 9001, 1080}
    _SUSPECT_PROCS = {"nc", "ncat", "netcat", "mimikatz", "psexec", "meterpreter",
                      "powercat", "chisel", "ligolo", "socat", "responder"}

    def _defense_snapshot(self) -> dict:
        """Current listening ports + running process names."""
        ports, procs = set(), set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_LISTEN and c.laddr:
                    ports.add(c.laddr.port)
        except Exception:
            pass
        try:
            for p in psutil.process_iter(["name"]):
                n = (p.info.get("name") or "").lower()
                if n:
                    procs.add(n)
        except Exception:
            pass
        return {"ports": sorted(ports), "procs": sorted(procs)}

    def set_security_baseline(self) -> dict:
        """Snapshot the current host state as known-good."""
        snap = self._defense_snapshot()
        try:
            os.makedirs(os.path.dirname(self._DEFENSE_BASELINE), exist_ok=True)
            with open(self._DEFENSE_BASELINE, "w", encoding="utf-8") as f:
                json.dump(snap, f)
        except Exception as e:
            return {"success": False, "message": f"Couldn't save baseline: {e}", "data": {}}
        return {"success": True,
                "message": f"Security baseline set, boss — {len(snap['ports'])} listening ports and "
                           f"{len(snap['procs'])} processes noted. I'll flag anything new.",
                "data": snap}

    def _remote_ip_intel(self, max_ips: int = 5) -> list:
        """threat_intel enrichment (#8): established OUTBOUND connections to PUBLIC remote IPs,
        reputation-checked via threat_intel (DShield is no-key). A malicious remote IP your host
        is talking to is the real 'context on change' a port/proc diff can't give. Capped + graceful."""
        try:
            from config import DEFENSE_INTEL as _on
        except Exception:
            _on = True
        if not _on:
            return []
        import ipaddress
        ips = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                    try:
                        a = ipaddress.ip_address(c.raddr.ip)
                        if not (a.is_private or a.is_loopback or a.is_link_local
                                or a.is_multicast or a.is_reserved):
                            ips.add(c.raddr.ip)
                    except Exception:
                        pass
        except Exception:
            pass
        flagged = []
        try:
            from core import threat_intel
            for ip in list(ips)[:max_ips]:
                try:
                    v = threat_intel.lookup(ip)
                    if (v.get("verdict") or "").lower() in ("malicious", "suspicious"):
                        flagged.append({"ip": ip, "verdict": v["verdict"], "summary": v.get("summary", "")})
                except Exception:
                    continue
        except Exception:
            pass
        return flagged

    def defensive_scan(self) -> dict:
        """Compare the host against its baseline; flag new ports/processes + known-bad +
        reputation-check the public IPs the host is connected to (threat_intel enrichment)."""
        snap = self._defense_snapshot()
        bad_ips = self._remote_ip_intel()

        baseline = None
        try:
            if os.path.exists(self._DEFENSE_BASELINE):
                with open(self._DEFENSE_BASELINE, "r", encoding="utf-8") as f:
                    baseline = json.load(f)
        except Exception:
            baseline = None

        # always call out known-bad ports/procs, baseline or not
        bad_ports = sorted(p for p in snap["ports"] if p in self._SUSPECT_PORTS)
        bad_procs = sorted(n for n in snap["procs"]
                           if any(s == n or s == os.path.splitext(n)[0] for s in self._SUSPECT_PROCS))

        if baseline is None:
            self.set_security_baseline()
            extra = ""
            if bad_ports or bad_procs:
                extra = " Heads up though — " + self._defense_flags(bad_ports, bad_procs)
            return {"success": True,
                    "message": f"No baseline yet, so I just set one from your current system.{extra}",
                    "data": {"snapshot": snap, "suspicious": {"ports": bad_ports, "procs": bad_procs}}}

        new_ports = sorted(set(snap["ports"]) - set(baseline.get("ports", [])))
        new_procs = sorted(set(snap["procs"]) - set(baseline.get("procs", [])))

        # build a spoken report
        if not new_ports and not new_procs and not bad_ports and not bad_procs and not bad_ips:
            msg = "All clear, boss. Nothing new listening, no suspicious processes, and the IPs " \
                  "you're connected to look clean since your baseline."
        else:
            bits = []
            if bad_ips:
                bits.append("RED FLAG — malicious/suspicious remote IP(s) connected: "
                            + ", ".join(f"{x['ip']} ({x['verdict']})" for x in bad_ips))
            if bad_ports or bad_procs:
                bits.append("RED FLAG — " + self._defense_flags(bad_ports, bad_procs))
            if new_ports:
                bits.append(f"{len(new_ports)} new listening port"
                            f"{'s' if len(new_ports) != 1 else ''}: {', '.join(map(str, new_ports[:8]))}")
            if new_procs:
                bits.append(f"{len(new_procs)} new process"
                            f"{'es' if len(new_procs) != 1 else ''}: {', '.join(new_procs[:6])}")
            msg = "Since your baseline: " + "; ".join(bits) + "."

        return {"success": True, "message": msg,
                "data": {"new_ports": new_ports, "new_procs": new_procs,
                         "suspicious": {"ports": bad_ports, "procs": bad_procs},
                         "bad_remote_ips": bad_ips, "snapshot": snap}}

    def _defense_flags(self, bad_ports, bad_procs) -> str:
        parts = []
        if bad_ports:
            parts.append(f"known backdoor port(s) open: {', '.join(map(str, bad_ports))}")
        if bad_procs:
            parts.append(f"attacker-tool process(es) running: {', '.join(bad_procs)}")
        return " and ".join(parts)

    # =====================================
    # TARGET MONITOR (mapper-lite: snapshot a target, diff vs last, alert on change)
    # Inspired by the "mapper watches for changes" workflow — a status-code flip or
    # new subdomain/JS endpoint on a known target is the cheap lead worth a human look.
    # Heuristic, not LLM-judged: avoids the model "hyping" noise into findings.
    # =====================================
    def _target_snapshot(self, target: str) -> dict:
        """Cheap recon snapshot of a target: HTTP fingerprint + subdomain set."""
        import json as _json
        snap = {"target": target, "ts": datetime.datetime.now().isoformat(),
                "http": {}, "subdomains": []}

        # _resolve_scheme picks a live scheme and pins localhost -> 127.0.0.1
        # (Go tools default to IPv6 ::1, which local IPv4-only servers don't answer).
        probe = _resolve_scheme(target)

        # HTTP fingerprint via httpx JSON (status/title/server/tech/content-length)
        out = run_cmd(["httpx", "-u", probe, "-json", "-silent", "-title",
                       "-tech-detect", "-status-code", "-content-length", "-web-server"],
                      timeout=30)
        if "Tool not found" not in out:
            for line in out.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    j = _json.loads(line)
                except Exception:
                    continue
                snap["http"] = {
                    "status": j.get("status_code"),
                    "title": (j.get("title") or "")[:120],
                    "server": j.get("webserver") or "",
                    "tech": sorted(j.get("tech") or j.get("technologies") or []),
                    "content_length": j.get("content_length"),
                }
                break

        # Subdomain set (only meaningful for a bare domain, but harmless otherwise)
        host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        if host.count(".") >= 1 and not host.replace(".", "").isdigit():
            sub = self.subfinder(host)
            snap["subdomains"] = sorted(set(sub.get("data", {}).get("subdomains", [])))
        return snap

    def _diff_target_snapshot(self, old: dict, new: dict) -> list:
        """Return human-readable meaningful changes between two snapshots. [] = no change."""
        changes = []
        oh, nh = (old or {}).get("http", {}) or {}, (new or {}).get("http", {}) or {}
        if oh.get("status") != nh.get("status") and nh.get("status") is not None:
            changes.append(f"status {oh.get('status')} -> {nh.get('status')}")
        if oh.get("server") != nh.get("server") and (oh.get("server") or nh.get("server")):
            changes.append(f"server '{oh.get('server')}' -> '{nh.get('server')}'")
        if oh.get("title") != nh.get("title") and (oh.get("title") or nh.get("title")):
            changes.append("title changed")
        ot, nt = set(oh.get("tech") or []), set(nh.get("tech") or [])
        if ot != nt:
            added, removed = nt - ot, ot - nt
            if added:   changes.append("tech + " + ", ".join(sorted(added)[:5]))
            if removed: changes.append("tech - " + ", ".join(sorted(removed)[:5]))
        ocl, ncl = oh.get("content_length"), nh.get("content_length")
        if isinstance(ocl, int) and isinstance(ncl, int) and ocl > 0:
            if abs(ncl - ocl) > max(200, ocl * 0.20):   # >20% and >200 bytes
                changes.append(f"size {ocl} -> {ncl}")
        new_subs = set(new.get("subdomains") or []) - set(old.get("subdomains") or [])
        if new_subs:
            shown = ", ".join(sorted(new_subs)[:8])
            extra = f" (+{len(new_subs) - 8} more)" if len(new_subs) > 8 else ""
            changes.append(f"new subdomain(s): {shown}{extra}")
        return changes

    def watch_target(self, target: str) -> dict:
        """Add a target to the change-monitor watchlist. Scope-gated: refuses out-of-scope."""
        target = (target or "").strip()
        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}
        if _in_scope(target) == "out":
            return {"success": False,
                    "message": f"Refused: {target} is OUT of scope. Not watching it.", "data": {}}
        rows = _load_target_watch()
        if any(r.get("target") == target for r in rows):
            return {"success": True, "message": f"Already watching {target}.", "data": {}}
        snap = self._target_snapshot(target)
        now = datetime.datetime.now().isoformat()
        rows.append({"target": target, "snapshot": snap, "added": now,
                     "last_checked": now, "last_change": None})
        _save_target_watch(rows)
        st = snap.get("http", {}).get("status")
        nsub = len(snap.get("subdomains") or [])
        return {"success": True,
                "message": f"Now watching {target} for changes. Baseline: HTTP {st}, "
                           f"{nsub} subdomain(s). I'll alert on meaningful change.",
                "data": {"snapshot": snap}}

    def unwatch_target(self, target: str) -> dict:
        target = (target or "").strip()
        rows = _load_target_watch()
        kept = [r for r in rows if r.get("target") != target]
        if len(kept) == len(rows):
            return {"success": False, "message": f"Not watching {target}.", "data": {}}
        _save_target_watch(kept)
        return {"success": True, "message": f"Stopped watching {target}.", "data": {}}

    def list_watched(self) -> dict:
        rows = _load_target_watch()
        if not rows:
            return {"success": True, "message": "No targets being watched. Say 'watch target X'.",
                    "data": {"targets": []}}
        lines = []
        for r in rows:
            st = r.get("snapshot", {}).get("http", {}).get("status")
            chg = r.get("last_change")
            lines.append(f"- {r['target']} (HTTP {st}" + (f", last change {chg[:16]}" if chg else "") + ")")
        return {"success": True, "message": f"Watching {len(rows)} target(s):\n" + "\n".join(lines),
                "data": {"targets": rows}}

    def monitor_targets(self) -> dict:
        """Re-snapshot every watched target, diff vs last, push an alert on meaningful change.
        Called on a schedule by the proactive engine (or 'check targets now')."""
        rows = _load_target_watch()
        if not rows:
            return {"success": True, "message": "No targets to monitor.", "data": {"changed": []}}
        try:
            from core import notify
        except Exception:
            notify = None
        changed = []
        for r in rows:
            target = r.get("target")
            if _in_scope(target) == "out":
                continue
            new = self._target_snapshot(target)
            diffs = self._diff_target_snapshot(r.get("snapshot", {}), new)
            r["snapshot"] = new
            r["last_checked"] = datetime.datetime.now().isoformat()
            if diffs:
                r["last_change"] = r["last_checked"]
                summary = f"Target change on {target}: " + "; ".join(diffs[:6])
                changed.append({"target": target, "changes": diffs})
                if notify:
                    notify.push(summary, kind="security")
                print(f"[ULTRON][monitor] {summary}")
        _save_target_watch(rows)
        msg = (f"Monitored {len(rows)} target(s) — {len(changed)} changed."
               if changed else f"Monitored {len(rows)} target(s) — no changes.")
        return {"success": True, "message": msg, "data": {"changed": changed}}

    # =====================================
    # FILE SCAN
    # =====================================
    def file_scan(self, path: str) -> dict:
        if not path:
            return {"success": False, "message": "File path missing.", "data": {}}

        if not os.path.exists(path):
            return {"success": False, "message": "File not found.", "data": {"path": path}}

        try:
            risks = []
            _, ext = os.path.splitext(path)

            if ext.lower() in [".exe", ".bat", ".ps1", ".sh"]:
                risks.append("Executable file detected")

            size = os.path.getsize(path)
            if size > 50 * 1024 * 1024:
                risks.append("Large file — verify source")

            message = "File appears safe." if not risks else "File risks:\n" + "\n".join(risks)

            return {
                "success": True,
                "message": message,
                "data": {"path": path, "risks": risks, "size_bytes": size}
            }
        except Exception as e:
            return {"success": False, "message": str(e), "data": {}}

    # =====================================
    # VIRUSTOTAL SCAN (Phase 30b)
    # =====================================
    def playbook_recall(self, query: str = "", stack: str = "") -> dict:
        return knowledge.playbook_recall(query, stack)

    def remember_technique(self, text: str, vuln_class: str = "manual", stack: str = "") -> dict:
        return knowledge.remember_technique(text, vuln_class, stack)

    @staticmethod
    def _render_text(url: str, timeout: int = 30) -> str:
        """Render a JS/SPA page in headless Chromium and return its visible text.
        HackerOne, Medium-react, etc. ship a JS shell — a plain fetch gets "enable
        JavaScript", not the report. Returns '' if Playwright is absent or it fails."""
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return ""
        try:
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True)
                # a real UA dodges bot-detection that serves a stripped shell (HackerOne does this);
                # scroll + a longer settle let lazy GraphQL content (the report body) render.
                pg = b.new_page(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
                pg.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                pg.wait_for_timeout(3500)
                try:
                    pg.mouse.wheel(0, 3000); pg.wait_for_timeout(2500)
                except Exception:
                    pass
                txt = pg.inner_text("body")
                b.close()
                return txt or ""
        except Exception:
            return ""

    @staticmethod
    def _crawl4ai_markdown(url: str) -> str:
        """Optional accelerator (#9): if crawl4ai is installed, use its Playwright render +
        clean-markdown extraction (better on ramble-heavy blog pages). Returns '' when it's
        not installed or fails — the caller falls back to safe_get + MarkItDown + our nav-strip,
        so this is a pure upgrade with zero hard dependency. `pip install crawl4ai && crawl4ai-setup`."""
        try:
            from crawl4ai import AsyncWebCrawler
            import asyncio
        except Exception:
            return ""
        try:
            async def _run():
                async with AsyncWebCrawler(verbose=False) as crawler:
                    res = await crawler.arun(url=url)
                    return (getattr(res, "markdown", "") or "")
            return asyncio.run(_run())
        except Exception:
            return ""

    @staticmethod
    def _render_text_html(url: str, timeout: int = 30) -> str:
        """Render a page in headless Chromium and return its full HTML (for link extraction
        from JS-built index pages). '' if Playwright absent / fails."""
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return ""
        try:
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True)
                pg = b.new_page(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
                pg.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                pg.wait_for_timeout(2500)
                html = pg.content()
                b.close()
                return html or ""
        except Exception:
            return ""

    @staticmethod
    def _clean_writeup_text(md: str, limit: int = 6000) -> str:
        """Strip site nav/boilerplate from a MarkItDown dump so the real writeup content
        (prose + payloads + code) reaches the LLM. Pages lead with menus — feeding the
        first N raw chars grabs the menu, not the bug. Keep substantive lines only."""
        keep, in_code = [], False
        for ln in (md or "").splitlines():
            s = ln.strip()
            if s.startswith("```"):
                in_code = not in_code; keep.append(ln); continue
            if in_code:
                keep.append(ln); continue
            if not s:
                continue
            # drop pure-navigation lines: short, or mostly markdown links / menu items
            links = len(re.findall(r"\[[^\]]*\]\([^)]*\)", s))
            stripped = re.sub(r"\[[^\]]*\]\([^)]*\)", "", s).strip()
            if links and len(stripped) < 15:            # a line that's basically just link(s)
                continue
            # keep real prose (long lines) or anything code-ish (payloads/requests/signatures)
            if len(s) >= 40 or any(c in s for c in "/'`;=<>$|") or s.startswith(("#", "-", "*", ">")):
                keep.append(s)
        out = "\n".join(keep)
        return out[:limit]

    @staticmethod
    def _parse_writeup_json(raw: str) -> list:
        """Pull the JSON array of techniques out of an LLM reply (tolerates ```json
        fences + surrounding prose). Returns [] on anything unparseable."""
        import json as _json
        s = (raw or "").strip()
        if "```" in s:                                  # strip code fences
            m = re.search(r"```(?:json)?\s*(.+?)```", s, re.DOTALL)
            if m:
                s = m.group(1).strip()
        a, b = s.find("["), s.rfind("]")                # isolate the array
        if a == -1 or b == -1 or b < a:
            return []
        try:
            arr = _json.loads(s[a:b + 1])
        except Exception:
            return []
        out = []
        for e in arr if isinstance(arr, list) else []:
            if isinstance(e, dict) and (e.get("technique") or "").strip():
                out.append(e)
        return out

    def ingest_writeup(self, url: str, max_chars: int = 7000) -> dict:
        """Learn from a public bug-bounty writeup: fetch the page (SSRF-guarded), distil
        the techniques with the local LLM, and add them to the playbook with verify=True
        so you eyeball them before they rank as proven. Local-only — data/playbook.json is
        gitignored, so anything captured stays on your machine."""
        if not url or not re.match(r"https?://", url.strip(), re.IGNORECASE):
            return {"success": False, "message": "Give a writeup URL (http/https).", "data": {}}
        url = url.strip()
        # Preferred path (#9): crawl4ai render+clean-markdown if installed (better extraction);
        # returns '' when absent -> we fall back to safe_get + MarkItDown + nav-strip below.
        text = self._clean_writeup_text(self._crawl4ai_markdown(url), limit=max_chars)
        # fetch -> clean text (safe_get validates every redirect hop; MarkItDown -> markdown)
        from core.url_guard import safe_get
        import tempfile as _tf, os as _os
        if len(text.strip()) < 120:
            try:
                resp = safe_get(url)
            except ValueError as e:
                return {"success": False, "message": f"Refused to fetch — {e}.", "data": {}}
            except Exception as e:
                return {"success": False, "message": f"Fetch failed: {str(e)[:80]}", "data": {}}
            try:
                from markitdown import MarkItDown
                from urllib.parse import urlsplit as _usplit
                ext = _os.path.splitext(_usplit(url).path)[1] or ".html"
                with _tf.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    tmp.write(resp.content); tp = tmp.name
                try:
                    raw_md = MarkItDown().convert(tp).text_content or ""
                    text = self._clean_writeup_text(raw_md, limit=max_chars)
                finally:
                    try: _os.remove(tp)
                    except Exception: pass
            except Exception as e:
                return {"success": False, "message": f"Could not extract text: {str(e)[:80]}", "data": {}}
        # JS-SPA fallback (HackerOne / Medium-react / etc): a plain fetch returns a
        # "enable JavaScript" shell — render in headless Chromium and use the visible text.
        if len(text.strip()) < 300 or "javascript is disabled" in text.lower() or "enable javascript" in text.lower():
            rendered = self._render_text(url)
            if rendered:
                text = self._clean_writeup_text(rendered, limit=max_chars)
        if len(text.strip()) < 120:
            return {"success": False, "message": "Writeup text too short / not extractable "
                                                 "(JS-heavy page and Playwright unavailable?).", "data": {}}

        # distil -> JSON techniques (local LLM, deterministic)
        prompt = (
            "Extract the reusable attack techniques from this bug-bounty writeup for a pentest "
            "playbook. Output ONLY a JSON array (no prose). Each item: "
            '{"class","stack","technique","payload","tell"} where class is the vuln type '
            "(sqli/xss/idor/ssrf/nosqli/ssti/lfi/auth-bypass/rce/open-redirect/csrf/xxe/race/"
            "jwt/graphql...), technique is one sentence on the trigger+how, payload is the exact "
            "payload/request if shown (else empty), tell is the signal it worked. Max 8. If none, [].\n\n"
            "WRITEUP:\n" + text
        )
        # explicit options: a big-enough context window for the writeup (default num_ctx
        # truncates long pages -> empty []) + room for the JSON array + low temp for structure.
        techs = []
        for _try in range(2):                            # qwen is non-deterministic; one retry on empty
            raw = ask_llm(prompt, agent="ultron", autotune_on=False,
                          params={"num_ctx": 8192, "num_predict": 1200, "temperature": 0.1})
            techs = self._parse_writeup_json(raw)
            if techs:
                break
        if not techs:
            return {"success": True, "data": {"added": 0, "url": url},
                    "message": "Fetched the writeup but distilled no clear techniques. "
                               "Try 'remember technique: ...' to add one by hand."}
        from core import playbook as pb
        added, ids = 0, []
        for t in techs[:12]:
            r = pb.add(t.get("class") or "misc", (t.get("technique") or "").strip(),
                       stack=t.get("stack", ""), payload=t.get("payload", ""),
                       tell=t.get("tell", ""), source="writeup", ref=url, verify=True)
            if r.get("added"):
                added += 1; ids.append(r["id"])
        return {"success": True,
                "message": f"Learned {added} new technique(s) from the writeup "
                           f"({len(techs)} distilled, {len(techs) - added} already known). "
                           f"Tagged verify — run 'playbook needs verify' to review/promote.",
                "data": {"added": added, "ids": ids, "distilled": len(techs), "url": url}}

    def ingest_feed(self, index_url: str, max_articles: int = 10) -> dict:
        """Feed-poller: point at a writeup-INDEX page (PentesterLand list, a 'top writeups'
        page, your bookmarks export), pull the article links, and ingest_writeup each one —
        turning a curated list into playbook techniques in one shot. Same-page nav/social links
        are filtered out. Capped + polite. Local-only (playbook is gitignored)."""
        import time
        from urllib.parse import urlsplit
        if not index_url or not re.match(r"https?://", index_url.strip(), re.IGNORECASE):
            return {"success": False, "message": "Give a writeup-index URL (http/https).", "data": {}}
        index_url = index_url.strip()
        from core.url_guard import safe_get
        try:
            resp = safe_get(index_url)
            text_html = resp.text or ""
        except Exception as e:
            return {"success": False, "message": f"Fetch failed: {str(e)[:80]}", "data": {}}
        if "javascript is disabled" in text_html.lower() or len(text_html) < 300:
            text_html = self._render_text_html(index_url) or text_html
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text_html, "html.parser")
        except Exception:
            return {"success": False, "message": "Could not parse the index page.", "data": {}}
        host = urlsplit(index_url).netloc
        _SOCIAL = ("twitter.com", "x.com", "facebook.com", "linkedin.com", "youtube.com",
                   "github.com/sponsors", "t.me", "discord", "/tag/", "/category/", "/author/")
        links, seen = [], set()
        for a in soup.find_all("a", href=True):
            h = a["href"].strip()
            if not h.startswith("http"):
                continue
            netloc = urlsplit(h).netloc
            # external article links (skip same-host nav + social/aggregator chrome)
            if netloc == host or any(s in h.lower() for s in _SOCIAL):
                continue
            if len(urlsplit(h).path) < 6:                 # bare domains = not an article
                continue
            if h not in seen:
                seen.add(h); links.append(h)
        if not links:
            return {"success": True, "data": {"added": 0, "articles": 0},
                    "message": "No external article links found on that index page."}
        links = links[:max_articles]
        total_added = ok = 0
        per = []
        for u in links:
            try:
                r = self.ingest_writeup(u)
            except Exception:
                continue
            a = r.get("data", {}).get("added")
            if r.get("success") and a is not None:
                ok += 1; total_added += a or 0; per.append((u, a or 0))
            time.sleep(1.0)
        return {"success": True,
                "message": f"Feed: ingested {ok}/{len(links)} articles, +{total_added} new technique(s) "
                           f"(tagged verify). Source: {index_url}",
                "data": {"added": total_added, "articles": ok, "per": per, "index": index_url}}

    # =====================================
    # MULTI-USER AUTHZ (Tier-1: session_manager B1 + request_mutator B2 + IDOR oracle B3)
    # The state engine — replay a request as different principals to find IDOR/BOLA/BAC,
    # the highest-frequency real-bounty class the single-session probes can't reach.
    # =====================================
    def session_set(self, name: str, cookie: str = "", bearer: str = "", role: str = "user") -> dict:
        """Register a named principal (anon/userA/userB/admin) from a cookie you already have
        (browser/login capture) or a bearer token. The basis for multi-user authz testing."""
        from core import session_manager as sm
        headers = {"Authorization": f"Bearer {bearer}"} if bearer else None
        if not name:
            return {"success": False, "message": "Give a session name (e.g. userA).", "data": {}}
        sm.set_session(name, cookie=cookie, headers=headers, role=role)
        return {"success": True, "data": {"name": name, "role": role},
                "message": f"Session '{name}' set (role={role}). Now: idor check <url> as {name} vs <other>."}

    def session_list(self) -> dict:
        from core import session_manager as sm
        s = sm.list_sessions()
        if not s:
            return {"success": True, "data": {"sessions": {}},
                    "message": "No sessions set. Use: session set userA cookie <cookie>."}
        lines = ["Sessions:"] + [f"  {n} (role={v.get('role')}) "
                                 f"{'cookie' if v.get('cookie') else ''}{' +bearer' if v.get('headers') else ''}"
                                 for n, v in s.items()]
        return {"success": True, "message": "\n".join(lines), "data": {"sessions": s}}

    def replay_as(self, name: str, url: str, method: str = "GET", body: str = "", force: bool = False) -> dict:
        """Fire a request AS a named principal (their cookie/token). The replay primitive.
        Destructive requests (delete/reset/payment/logout/invite or DELETE/PUT) are REFUSED
        unless force=True — multi-user replay must not trigger side effects on a live target."""
        from core import session_manager as sm
        h = sm.headers_for(name)
        if h is None:
            return {"success": False, "message": f"No session '{name}'. Set it first.", "data": {}}
        if _is_destructive(url, method) and not force:
            return {"success": False, "data": {"blocked": True},
                    "message": f"REFUSED: {method} {url} looks destructive (state-changing / costs money / "
                               f"sends a notification). Replaying it as '{name}' could harm a live target. "
                               f"Pass force=True only if you're certain it's safe + authorized."}
        try:
            if method.upper() in ("POST", "PUT", "PATCH"):
                import json as _json
                try:
                    jb = _json.loads(body) if body else None
                except Exception:
                    jb = None
                r = _http_post(url, json_body=jb, data=(None if jb else (body or None)), headers=h)
            else:
                r = _http_get(url, headers=h)
            return {"success": True,
                    "message": f"[{name}] {method} {url} -> HTTP {r.status_code}, {len(r.text or '')}b",
                    "data": {"status": r.status_code, "len": len(r.text or ""), "body": (r.text or "")[:400]}}
        except Exception as e:
            return {"success": False, "message": f"replay failed: {str(e)[:80]}", "data": {}}

    def idor_check(self, url: str, owner: str = "userA", attacker: str = "userB") -> dict:
        """BOLA/IDOR oracle (B3): fetch an owner-specific resource as the OWNER, then as the
        ATTACKER (same URL + id-swapped variants), with an ANON control. Flags when the attacker
        gets the owner's resource AND anon is denied (the anon control kills the 'it's just public'
        false positive). Findings are CANDIDATES (validated=False) — confirm the leaked data is
        truly the other user's with your two real accounts. Authorized targets only."""
        from core import session_manager as sm, request_mutator as rm
        ho, ha = sm.headers_for(owner), sm.headers_for(attacker)
        if ho is None or ha is None:
            return {"success": False, "data": {},
                    "message": f"Set both sessions first: 'session set {owner} cookie ..' and "
                               f"'session set {attacker} cookie ..'."}

        def fetch(u, h):
            try:
                r = _http_get(u, headers=h or {})
                return r.status_code, len(r.text or ""), (r.text or "")
            except Exception:
                return None, 0, ""

        so, lo, bo = fetch(url, ho)
        if so != 200 or lo < 1:
            return {"success": True, "data": {"findings": []},
                    "message": f"Owner '{owner}' didn't get a 200 resource at {url} (HTTP {so}) — "
                               f"nothing to test. Point at a resource the owner can read."}

        def _close(a, b):
            return abs(a - b) <= max(40, int(lo * 0.05))

        findings = []
        # (1) same-URL BOLA: attacker reads the owner's resource; anon cannot.
        sa, la, ba = fetch(url, ha)
        sn, ln, _ = fetch(url, {})
        anon_denied = not (sn == 200 and _close(ln, lo))
        bola = sa == 200 and _close(la, lo) and anon_denied
        if bola:
            findings.append({
                "template": "idor-bola", "severity": "high", "url": url, "cve": None, "validated": False,
                "evidence": f"'{attacker}' got HTTP 200/{la}b at {url} (owner saw 200/{lo}b) while anon was "
                            f"denied (HTTP {sn}) — the attacker reads the owner's resource = broken object-level "
                            f"authorization. CONFIRM the data is {owner}'s, not {attacker}'s own.",
                "repro": [f"As {owner}: GET {url} -> 200/{lo}b", f"As {attacker}: GET {url} -> 200/{la}b",
                          f"As anon: GET {url} -> {sn}", "Confirm with two real accounts that the data is the owner's"],
            })
            # (2) id-swap enumeration — ONLY meaningful when ownership ISN'T enforced (BOLA held);
            #     otherwise the attacker swapping to THEIR OWN id legitimately returns 200 (= a false
            #     positive). Gating enum behind BOLA makes it a corroborating signal, not a noisy one.
            for var in rm.mutate_url(url)[:8]:
                sv, lv, bv = fetch(var["url"], ha)
                if sv == 200 and lv > 0 and bv != ba and bv != bo and _close(lv, lo):
                    findings.append({
                        "template": "idor-enum", "severity": "high", "url": var["url"], "cve": None, "validated": False,
                        "evidence": f"As '{attacker}', {var['label']} returned a DIFFERENT 200/{lv}b record "
                                    f"({var['why']}) on an endpoint with no ownership check — objects are enumerable "
                                    f"across the id space.",
                        "repro": [f"As {attacker}: GET {var['url']} -> 200/{lv}b (a different record)",
                                  "Iterate the id to enumerate other users' objects; confirm ownership"],
                    })
                    break    # one enum signal per endpoint is enough
        # exploitability memory: bank each candidate as a hypothesis on the target profile
        try:
            from core import target_profiles as tp
            for f in findings:
                tp.record_hypothesis(_clean_site(url), f["url"], f["template"],
                                     rationale=(f.get("evidence") or "")[:120], status="candidate")
        except Exception:
            pass
        msg = (f"IDOR/BOLA: {len(findings)} candidate(s) at {url}." if findings
               else f"No cross-principal access at {url} — attacker didn't get the owner's resource (good auth).")
        return {"success": True, "message": msg, "data": {"findings": findings}}

    # fields whose auto-mutation would lock a user out / alter privilege or funds — refuse to
    # write-test them (that's manual-only). The safe write-BOLA probe only touches benign,
    # trivially-reversible fields (e.g. email, display name).
    _WBOLA_UNSAFE_FIELDS = ("password", "passwd", "secret", "token", "balance", "amount",
                            "role", "admin", "permission", "priv", "pin", "otp", "mfa", "2fa",
                            "key", "credit", "fund", "wallet", "owner")

    def write_bola_check(self, url: str, field: str = "email", owner: str = "userA",
                         attacker: str = "userB", method: str = "PUT", verify_url: str = "") -> dict:
        """OPT-IN write-BOLA oracle: does the ATTACKER's session MUTATE a field on the OWNER's
        object? Read-only idor_check misses this (the highest-value BOLA class — e.g. changing
        another user's email -> account takeover). SAFE by design: writes ONE benign, reversible
        field with a unique marker, confirms the change landed on the OWNER's resource, then
        REVERTS it. Refuses destructive fields (password/balance/role/...). NOT wired into
        bug_bounty — call explicitly, on authorized targets, with your own two accounts only.

        url = the write target (PUT/PATCH). verify_url = where to GET the object to confirm the
        change (defaults to url; set it for sub-resource writes like VAmPI's /users/{u}/email)."""
        from core import session_manager as sm
        ho, ha = sm.headers_for(owner), sm.headers_for(attacker)
        if ho is None or ha is None:
            return {"success": False, "data": {},
                    "message": f"Set both sessions first: 'session set {owner} ..' and 'session set {attacker} ..'."}
        fl = (field or "").lower()
        if any(bad in fl for bad in self._WBOLA_UNSAFE_FIELDS):
            return {"success": False, "data": {},
                    "message": f"Refusing to auto-write destructive field '{field}' (would lock out / alter "
                               f"privilege or funds). Test that one manually."}
        import time as _t
        vurl = verify_url or url

        def getj(h):
            try:
                r = _http_get(vurl, headers=h or {})
                return r.status_code, (r.json() if (r.text or "").strip() else {})
            except Exception:
                return None, {}

        so, jo = getj(ho)
        if so != 200 or not isinstance(jo, dict) or field not in jo:
            return {"success": True, "data": {"findings": []},
                    "message": f"Owner didn't return a JSON object carrying field '{field}' at {vurl} "
                               f"(HTTP {so}) — nothing to write-test."}
        original = jo[field]
        stamp = int(_t.time())
        marker = (f"wbola{stamp}@example.com" if ("@" in str(original) or "email" in fl)
                  else f"wbola-marker-{stamp}")

        try:
            wr = _http_write(method, url, json_body={field: marker}, headers=ha)
            wcode = wr.status_code
        except Exception as e:
            return {"success": False, "data": {}, "message": f"Attacker write failed: {e}"}

        _t.sleep(0.2)
        sv, jv = getj(ho)
        landed = (sv == 200 and isinstance(jv, dict) and str(jv.get(field)) == marker)

        findings, reverted = [], None
        # revert whenever the write was ACCEPTED (2xx) — not only when it landed on the owner —
        # so a JWT-scoped endpoint that mutated the ATTACKER's own object is cleaned up too (no
        # dangling marker). Attacker session first (it made the write), then owner as fallback.
        _wrote = isinstance(wcode, int) and 200 <= wcode < 300
        if landed or _wrote:
            for h in (ha, ho):
                try:
                    _http_write(method, url, json_body={field: original}, headers=h)
                    _t.sleep(0.2)
                    _s, _j = getj(ho)
                    if isinstance(_j, dict) and str(_j.get(field)) == str(original):
                        reverted = True
                        break
                except Exception:
                    pass
        if landed:
            findings.append({
                "template": "idor-bola-write", "severity": "critical", "url": url, "cve": None,
                "validated": True,
                "evidence": (f"'{attacker}' wrote field '{field}' on '{owner}'s object at {url} (HTTP {wcode}) "
                             f"and the change was CONFIRMED on the owner's resource = write-BOLA (broken "
                             f"object-level authorization on mutation). "
                             + ("Value was reverted to the original." if reverted
                                else f"WARNING: automatic revert FAILED — restore '{field}' to {original!r} manually.")),
                "repro": [f"As {owner}: GET {url} -> {field}={original!r}",
                          f"As {attacker}: {method} {url}  body {{{field!r}: {marker!r}}}  -> HTTP {wcode}",
                          f"As {owner}: GET {url} -> {field}={marker!r}  (the attacker's write landed)",
                          "Impact: an attacker mutates another user's object (change email -> password-reset takeover)"],
            })

        msg = (f"WRITE-BOLA CONFIRMED at {url} (field '{field}')"
               + ("" if reverted else " — REVERT FAILED, restore manually") + "."
               if findings else
               f"No write-BOLA at {url} — attacker's write to '{field}' didn't land on the owner's object "
               f"(HTTP {wcode}, good auth).")
        return {"success": True, "message": msg, "data": {"findings": findings, "reverted": reverted}}

    def graphql_hunt(self, url: str, as_user: str = "") -> dict:
        """Hunt a GraphQL endpoint (Tier-2): introspection (schema exposure = info disclosure),
        operation inventory, flag privileged-looking mutations, and (if a session is set) check
        introspection is reachable as a low-priv principal. Mechanical capture — the human +
        request_mutator drive the per-operation authz tests. Authorized targets only."""
        import json as _json
        from core import session_manager as sm
        hdrs = {"Content-Type": "application/json"}
        if as_user:
            sh = sm.headers_for(as_user)
            if sh:
                hdrs.update(sh)
        introspection = ('{"query":"query{__schema{queryType{fields{name}} mutationType{fields{name}} '
                         'types{name kind}}}"}')
        try:
            r = _http_post(url, data=introspection, headers=hdrs)
            body = r.text or ""
            data = _json.loads(body)
        except Exception as e:
            return {"success": False, "data": {},
                    "message": f"Not a GraphQL endpoint / unreachable / non-JSON: {str(e)[:60]}"}
        schema = ((data.get("data") or {}) if isinstance(data, dict) else {}).get("__schema")
        if not schema:
            disabled = isinstance(data, dict) and ("errors" in data or "data" in data)
            return {"success": True, "data": {"introspection": False, "findings": []},
                    "message": (f"GraphQL at {url} — introspection DISABLED (good). Infer the schema from the "
                                "app's own queries or a wordlist; then test operations per-session."
                                if disabled else f"{url} did not return a GraphQL schema (not GraphQL?).")}
        queries = [f["name"] for f in (schema.get("queryType") or {}).get("fields") or [] if f.get("name")]
        muts = [f["name"] for f in (schema.get("mutationType") or {}).get("fields") or [] if f.get("name")]
        findings = [{
            "template": "graphql-introspection", "severity": "low", "url": url, "cve": None, "validated": True,
            "evidence": f"Introspection is ENABLED — full schema exposed ({len(queries)} queries, "
                        f"{len(muts)} mutations). Attackers map every operation + hidden fields.",
            "repro": [f"POST {url} the introspection query", "Map the schema; hunt hidden/admin operations"],
        }]
        _PRIV = re.compile(r"delete|remove|create|update|^set|grant|revoke|admin|role|password|"
                           r"promote|disable|reset|refund|transfer|impersonate|invite", re.I)
        priv = [m for m in muts if _PRIV.search(m)]
        if priv:
            findings.append({
                "template": "graphql-privileged-mutation", "severity": "medium", "url": url,
                "cve": None, "validated": False,
                "evidence": f"Privileged-looking mutations exposed (test per-operation authz as a low-priv "
                            f"user — call each as userB and confirm it's rejected): {', '.join(priv[:15])}",
                "repro": [f"As a low-priv session: mutation {{ {priv[0]}(...) }}",
                          "If a normal user can invoke an admin-only mutation = broken access control"],
            })
        gate = ("[as %s] " % as_user) if as_user else ""
        return {"success": True,
                "message": f"GraphQL {gate}at {url}: introspection ENABLED, {len(queries)} queries, "
                           f"{len(muts)} mutations, {len(priv)} privileged-looking. {len(findings)} finding(s).",
                "data": {"introspection": True, "queries": queries, "mutations": muts,
                         "privileged": priv, "findings": findings}}

    def target_dorks(self, target: str) -> dict:
        """Google dorks to recon a SPECIFIC target (TakSec set), with the target substituted in."""
        import json as _json
        host = re.sub(r"^https?://", "", (target or "").strip()).split("/")[0] or "example.com"
        try:
            doc = _json.load(open("data/target_dorks.json", encoding="utf-8"))
        except Exception:
            return {"success": False, "message": "target_dorks.json missing (run scripts/seed).", "data": {}}
        lines = [f"Target-recon dorks for {host} (paste into Google):", ""]
        for cat in doc.get("categories", []):
            lines.append(f"# {cat['category']}")
            for d in cat["dorks"][:2]:
                lines.append("  " + d.replace("example.com", host).replace("example[.]com", host))
        return {"success": True, "message": "\n".join(lines[:80]),
                "data": {"host": host, "categories": doc.get("categories", [])}}

    def find_programs(self, region: str = "") -> dict:
        """Recall program-discovery dorks (find bounty/RD programs). Run on Google —
        many use Google-only operators DuckDuckGo can't."""
        import json as _json
        try:
            doc = _json.load(open("data/recon_dorks.json", encoding="utf-8"))
        except Exception:
            return {"success": False, "message": "recon_dorks.json missing (run scripts/seed).", "data": {}}
        rows = doc.get("dorks", [])
        if region:
            rows = [d for d in rows if (d.get("region") or "") == region.lower()] or rows
        lines = [f"Program-discovery dorks{' (' + region + ')' if region else ''} — run on Google:", ""]
        lines += ["  " + d["dork"] for d in rows[:30]]
        return {"success": True, "message": "\n".join(lines), "data": {"count": len(rows)}}

    def threat_intel(self, ioc: str) -> dict:
        """Aggregate IOC reputation (IP/domain/URL/hash) across threat feeds.
        DShield is no-key (IPs); URLhaus/AbuseIPDB/OTX join when their keys are set."""
        if not ioc:
            return {"success": False, "message": "Give me an IOC: IP, domain, URL, or file hash.", "data": {}}
        from core import threat_intel as _ti
        r = _ti.lookup(ioc)
        lines = [r["summary"], ""]
        for s in r["sources"]:
            mark = {"malicious": "x", "suspicious": "!", "clean": "+",
                    "nokey": "·", "skip": "·", "error": "·", "unknown": "·"}.get(s["status"], "·")
            lines.append(f"  {mark} {s['source']}: {s['detail']}")
        return {"success": True, "message": "\n".join(lines),
                "data": {"verdict": r["verdict"], "kind": r["kind"], "sources": r["sources"]}}

    def vt_scan(self, target: str) -> dict:
        """Look up a file path, hash, URL, or domain in VirusTotal (v3 API).
        File paths are hashed locally (sha256) — file content never uploaded."""
        import hashlib as _hashlib
        import base64 as _base64
        import re as _re
        import json as _json
        import urllib.request, urllib.parse, urllib.error

        try:
            from config import VIRUSTOTAL_API_KEY as _vt_key
        except Exception:
            _vt_key = ""
        if not _vt_key:
            return {"success": False, "message": "VirusTotal key missing. Set VIRUSTOTAL_API_KEY in .env.", "data": {}}

        target = (target or "").strip().strip('"\'')
        if not target:
            return {"success": False, "message": "Nothing to scan. Give a file path, hash, URL, or domain.", "data": {}}

        # Determine target type -> VT v3 endpoint
        endpoint = None
        label = target
        kind = None
        try:
            if os.path.exists(target) and os.path.isfile(target):
                h = _hashlib.sha256()
                with open(target, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                sha = h.hexdigest()
                endpoint = f"/files/{sha}"
                label = os.path.basename(target)
                kind = "file"
            elif _re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", target):
                endpoint = f"/files/{target}"
                kind = "hash"
            elif _re.match(r"https?://", target, _re.IGNORECASE):
                url_id = _base64.urlsafe_b64encode(target.encode()).rstrip(b"=").decode()
                endpoint = f"/urls/{url_id}"
                kind = "url"
            elif _re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", target):
                endpoint = f"/ip_addresses/{target}"
                kind = "ip"
            elif _re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", target, _re.IGNORECASE):
                endpoint = f"/domains/{target}"
                kind = "domain"
            else:
                return {"success": False, "message": f"Couldn't classify '{target}' as file, hash, URL, or domain.", "data": {}}
        except Exception as e:
            return {"success": False, "message": f"VT target prep failed: {e}", "data": {}}

        url = "https://www.virustotal.com/api/v3" + endpoint
        req = urllib.request.Request(url, headers={"x-apikey": _vt_key, "User-Agent": "JARVIS-Ultron/1.0"})
        throttle("virustotal")   # 4/min free tier — space calls to avoid 429
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"success": True, "message": f"{label} not found in VirusTotal database (never scanned).", "data": {"kind": kind, "found": False}}
            if e.code == 401:
                return {"success": False, "message": "VirusTotal key invalid (401).", "data": {}}
            if e.code == 429:
                return {"success": False, "message": "VirusTotal rate limit hit (4/min, 500/day). Try shortly.", "data": {}}
            return {"success": False, "message": f"VirusTotal error {e.code}.", "data": {}}
        except Exception as e:
            return {"success": False, "message": f"VirusTotal request failed: {e}", "data": {}}

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = mal + susp + harmless + undetected + stats.get("timeout", 0)

        if total == 0:
            return {"success": True, "message": f"{label}: no analysis data available yet.", "data": {"kind": kind, "stats": stats}}

        if mal > 0:
            verdict = f"! MALICIOUS — {mal}/{total} engines flagged {label}"
            if susp:
                verdict += f" ({susp} also suspicious)"
        elif susp > 0:
            verdict = f"! SUSPICIOUS — {susp}/{total} engines flagged {label}, 0 malicious"
        else:
            verdict = f"+ CLEAN — {label}: 0/{total} detections"

        # Friendly name / reputation extras
        rep = attrs.get("reputation")
        extra = f" Reputation: {rep}." if isinstance(rep, int) and rep != 0 else ""

        return {
            "success": True,
            "message": verdict + "." + extra,
            "data": {"kind": kind, "malicious": mal, "suspicious": susp,
                     "harmless": harmless, "undetected": undetected, "total": total, "found": True}
        }

    # =====================================
    # LOG CHECK
    # =====================================
    def log_check(self) -> dict:
        try:
            if platform.system() == "Windows":
                return {
                    "success": True,
                    "message": "Windows Event Log monitoring coming soon.",
                    "data": {"platform": "Windows"}
                }

            log_path = "/var/log/syslog"
            if not os.path.exists(log_path):
                return {"success": False, "message": "Log file not accessible.", "data": {}}

            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-10:]

            suspicious = [
                l for l in lines
                if any(k in l.lower() for k in ["error", "failed", "denied"])
            ]

            message = (
                "No suspicious logs."
                if not suspicious
                else "Suspicious logs:\n" + "".join(suspicious[:5])
            )

            return {"success": True, "message": message, "data": {"suspicious": suspicious}}

        except Exception as e:
            return {"success": False, "message": str(e), "data": {}}

    # =====================================
    # CVE TRACKER (Phase 23)
    # =====================================
    def _load_watchlist(self) -> dict:
        if not os.path.exists(_CVE_FILE):
            return {}
        try:
            with open(_CVE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_watchlist(self, data: dict):
        os.makedirs("data", exist_ok=True)
        with open(_CVE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def cve_track(self, cve_id: str) -> dict:
        import re as _re
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        if not _re.match(r"CVE-\d{4}-\d+", cve_id):
            return {"success": False, "message": f"Invalid CVE ID: {cve_id}", "data": {}}

        watchlist = self._load_watchlist()
        if cve_id in watchlist:
            return {"success": True, "message": f"{cve_id} already tracked.", "data": {}}

        # Fetch initial data
        result = self.find_exploits(cve_id)
        nvd = result.get("data", {}).get("nvd", {})
        poc_count = result.get("data", {}).get("total", 0)

        entry = {
            "cve_id": cve_id,
            "date_added": datetime.datetime.now().isoformat(),
            "last_checked": datetime.datetime.now().isoformat(),
            "cvss_score": nvd.get("cvss_score"),
            "severity": nvd.get("severity"),
            "description": nvd.get("description", "")[:200],
            "affected": nvd.get("affected", []),   # CPE vendor:product list — for asset correlation
            "poc_count": poc_count,
            "status": "active"
        }

        watchlist[cve_id] = entry
        self._save_watchlist(watchlist)

        sev = entry["severity"] or "unknown"
        score = entry["cvss_score"] or "?"
        msg = f"Now tracking {cve_id}. CVSS {score} ({sev}). {poc_count} PoC{'s' if poc_count != 1 else ''} found so far."
        return {"success": True, "message": msg, "data": entry}

    def cve_list(self) -> dict:
        watchlist = self._load_watchlist()
        if not watchlist:
            return {"success": True, "message": "No CVEs being tracked. Say 'track CVE-YYYY-NNNN' to start.", "data": {}}

        lines = [f"Tracking {len(watchlist)} CVE{'s' if len(watchlist) != 1 else ''}:"]
        for cve_id, entry in sorted(watchlist.items()):
            score = entry.get("cvss_score") or "?"
            sev = (entry.get("severity") or "?").upper()
            pocs = entry.get("poc_count", 0)
            last = entry.get("last_checked", "")[:10]
            lines.append(f"  {cve_id}  CVSS:{score} ({sev})  PoCs:{pocs}  checked:{last}")

        return {"success": True, "message": "\n".join(lines), "data": {"watchlist": watchlist}}

    def cve_check(self, cve_id: str = None) -> dict:
        watchlist = self._load_watchlist()
        if not watchlist:
            return {"success": True, "message": "No CVEs tracked yet.", "data": {}}

        targets = [cve_id.upper()] if cve_id else list(watchlist.keys())
        updates = []

        for cid in targets:
            if cid not in watchlist:
                continue
            old = watchlist[cid]
            result = self.find_exploits(cid)
            nvd = result.get("data", {}).get("nvd", {})
            new_pocs = result.get("data", {}).get("total", 0)
            old_pocs = old.get("poc_count", 0)

            changed = new_pocs != old_pocs
            watchlist[cid]["last_checked"] = datetime.datetime.now().isoformat()
            watchlist[cid]["cvss_score"] = nvd.get("cvss_score") or old.get("cvss_score")
            watchlist[cid]["severity"] = nvd.get("severity") or old.get("severity")
            watchlist[cid]["poc_count"] = new_pocs

            if changed:
                diff = new_pocs - old_pocs
                sign = "+" if diff > 0 else ""
                updates.append(f"{cid}: PoC count changed {old_pocs} -> {new_pocs} ({sign}{diff})")
            else:
                updates.append(f"{cid}: No change ({new_pocs} PoCs)")

        self._save_watchlist(watchlist)

        msg = f"Checked {len(targets)} CVE{'s' if len(targets) != 1 else ''}:\n" + "\n".join(updates)
        return {"success": True, "message": msg, "data": {"checked": targets, "updates": updates}}

    def cve_untrack(self, cve_id: str) -> dict:
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        watchlist = self._load_watchlist()
        if cve_id not in watchlist:
            return {"success": False, "message": f"{cve_id} not in watchlist.", "data": {}}
        del watchlist[cve_id]
        self._save_watchlist(watchlist)
        return {"success": True, "message": f"Stopped tracking {cve_id}.", "data": {}}

    # =====================================
    # CVE -> ASSET CORRELATION (Phase 51 #9)
    # =====================================
    def correlate(self) -> dict:
        """Cross-link tracked CVEs against services found in scan history.
        Flags hosts running software a tracked CVE affects."""
        watchlist = self._load_watchlist()
        hist = _load_scan_history()

        if not watchlist:
            return {"success": True, "message": "No CVEs tracked. Add some with 'track CVE-YYYY-NNNN', then scan a host.", "data": {}}
        if not hist:
            return {"success": True, "message": "No scan history yet. Run a service scan first, e.g. 'service scan 10.0.0.5'.", "data": {}}

        findings = []
        for target, info in hist.items():
            services = info.get("ports", [])
            if not services:
                continue
            svc_toks = _service_tokens(services)
            for cve_id, entry in watchlist.items():
                cve_kws = _cve_product_keywords(entry)
                if not cve_kws:
                    continue
                matched = _match_products(cve_kws, svc_toks)
                if matched:
                    findings.append({
                        "target": target,
                        "cve_id": cve_id,
                        "severity": (entry.get("severity") or "?").upper(),
                        "cvss": entry.get("cvss_score") or "?",
                        "services": matched,
                    })

        if not findings:
            return {
                "success": True,
                "message": (
                    f"No correlations. Checked {len(watchlist)} tracked CVE(s) against "
                    f"{len(hist)} scanned host(s) — no tracked CVE matches running services. "
                    f"Tip: use 'service scan <target>' for version detection (better matches)."
                ),
                "data": {"findings": []},
            }

        # Sort: critical first, then by cvss
        _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "?": 9}
        findings.sort(key=lambda f: (_sev_rank.get(f["severity"], 9)))

        lines = [f"! {len(findings)} CVE-asset correlation(s) found:"]
        for f in findings:
            svc = ", ".join(f["services"])
            lines.append(
                f"  {f['cve_id']} ({f['severity']}, CVSS {f['cvss']}) -> "
                f"{f['target']} running {svc}"
            )

        return {
            "success": True,
            "message": "\n".join(lines),
            "data": {"findings": findings, "cve_count": len(watchlist), "host_count": len(hist)},
        }

    # =====================================
    # CVE SEARCH — NVD API v2 (Phase 30a)
    # =====================================
    def search_cve(self, keyword: str, severity: str = "", days_back: int = 7) -> dict:
        return cve_lookup.search_cve(keyword, severity, days_back)

    # =====================================
    # DNS LOOKUP (Phase 42)
    # =====================================
    def dns_lookup(self, target: str) -> dict:
        """Forward (hostname->IP) and reverse (IP->hostname) DNS. Pure stdlib socket."""
        import ipaddress
        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}
        target = target.strip()
        try:
            is_ip = True
            try:
                ipaddress.ip_address(target)
            except ValueError:
                is_ip = False

            if is_ip:
                hostname, _, _ = socket.gethostbyaddr(target)
                return {
                    "success": True,
                    "message": f"Reverse DNS: {target} -> {hostname}",
                    "data": {"ip": target, "hostname": hostname, "type": "reverse"}
                }
            else:
                _, _, ips = socket.gethostbyname_ex(target)
                ip_list = list(set(ips))[:5]
                ip_str = ", ".join(ip_list)
                return {
                    "success": True,
                    "message": f"DNS: {target} -> {ip_str}",
                    "data": {"hostname": target, "ips": ip_list, "type": "forward"}
                }
        except socket.herror:
            return {"success": False, "message": f"No reverse DNS record for {target}.", "data": {}}
        except socket.gaierror:
            return {"success": False, "message": f"DNS lookup failed: {target} not resolved.", "data": {}}
        except Exception as e:
            return {"success": False, "message": f"DNS error: {e}", "data": {}}

    # =====================================
    # HASH (Phase 42)
    # =====================================
    def hash_target(self, target: str, algorithm: str = "sha256") -> dict:
        """Hash a string or file. Algorithms: md5, sha1, sha256, sha512."""
        import hashlib
        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}
        algo = algorithm.lower().replace("-", "")
        if algo not in ("md5", "sha1", "sha256", "sha512"):
            algo = "sha256"
        try:
            h = hashlib.new(algo)
            if os.path.exists(target):
                # File hash
                with open(target, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                digest = h.hexdigest()
                size = os.path.getsize(target)
                return {
                    "success": True,
                    "message": f"{algo.upper()} of {os.path.basename(target)} ({size} bytes): {digest}",
                    "data": {"target": target, "algorithm": algo, "hash": digest, "type": "file"}
                }
            else:
                # String hash
                h.update(target.encode("utf-8"))
                digest = h.hexdigest()
                return {
                    "success": True,
                    "message": f"{algo.upper()} of '{target[:60]}': {digest}",
                    "data": {"target": target, "algorithm": algo, "hash": digest, "type": "string"}
                }
        except Exception as e:
            return {"success": False, "message": f"Hash error: {e}", "data": {}}

    # =====================================
    # HACKINGTOOL (Phase 36) — 180+ tools via native/WSL/Docker, scoped allowlist
    # =====================================
    def ht_preflight(self) -> dict:
        """Detect backend for the hackingtool fleet (native/WSL/Docker)."""
        from agents.ultron.hackingtool import ht_wrapper as _ht
        pf = _ht.ht_preflight()
        return {"success": pf["ready"], "message": pf["message"], "data": pf}

    def ht_search(self, query: str = "", category: str = "") -> dict:
        """Search the 180+ tool index. Flags which are in Ultron's allowlist."""
        from agents.ultron.hackingtool import ht_wrapper as _ht
        res = _ht.ht_search(query, category)
        runnable = [r["id"] for r in res["results"] if r["runnable"]]
        if not res["results"]:
            return {"success": True, "message": f"No tools match '{query}'.", "data": res}
        lines = [f"{r['id']} [{r['tier']}] — {r['title']}" for r in res["results"][:10]]
        msg = f"Found {res['count']} tool(s). Runnable: {len(runnable)}.\n" + "\n".join(lines)
        return {"success": True, "message": msg, "data": res}

    def ht_run(self, tool_id: str, args: str = "", allow_extended: bool = False) -> dict:
        """Run an allowlisted hackingtool. Gated: SAFE tier only unless allow_extended."""
        from agents.ultron.hackingtool import ht_wrapper as _ht
        res = _ht.ht_run(tool_id, args, allow_extended=allow_extended)
        status = res.get("status")
        if status == "ok":
            out = (res.get("stdout") or "").strip()
            summary = out[:1500] if out else "(no output)"
            return {"success": True,
                    "message": f"{tool_id} [{res.get('backend')}] +\n{summary}",
                    "data": res}
        if status in ("refused", "no_backend", "fallback"):
            return {"success": False, "message": res.get("message", status), "data": res}
        # error / timeout / unclassified
        err = res.get("message") or (res.get("stderr") or "")[:500] or status
        return {"success": False, "message": f"{tool_id} failed: {err}", "data": res}

    def setup_scope(self, text: str) -> dict:
        """Paste a bug-bounty program policy -> parse it (local LLM) -> set up the hunt:
        writes data/scope.json (in/out domains, enforced) + data/roe.json (out-of-scope vuln
        types filtered from findings, rate limit applied to tools, rules to remember).
        Then run 'bug bounty <in-scope-target>' — it'll respect all of this."""
        if not text or len(text.strip()) < 20:
            return {"success": False, "message": "Paste the program's in-scope / out-of-scope text.", "data": {}}
        print("[ULTRON] Parsing program scope with LLM...")
        p = parse_scope(text)
        if p.get("_error"):
            return {"success": False, "message": f"Couldn't parse scope: {p['_error']}", "data": p}
        import json as _json
        os.makedirs("data", exist_ok=True)
        scope = {"in_scope": p["in_scope_domains"], "out_of_scope": p["out_of_scope_domains"]}
        roe = {k: p[k] for k in ("in_scope_types", "out_of_scope_types",
                                 "rate_limit_rps", "max_concurrent", "rules")}
        try:
            _json.dump(scope, open(os.path.join("data", "scope.json"), "w", encoding="utf-8"), indent=2)
            _json.dump(roe, open(os.path.join("data", "roe.json"), "w", encoding="utf-8"), indent=2)
        except Exception as e:
            return {"success": False, "message": f"scope save failed: {e}", "data": {}}
        rl = roe.get("rate_limit_rps")
        msg = (
            "Scope set from the pasted policy — verify it's right:\n"
            f"  IN-SCOPE domains:     {', '.join(scope['in_scope']) or '(none stated — pass the target yourself)'}\n"
            f"  OUT-OF-SCOPE domains: {', '.join(scope['out_of_scope']) or '(none)'}\n"
            f"  Looking for:          {', '.join(roe['in_scope_types']) or 'any class'}\n"
            f"  Will NOT report:      {', '.join(roe['out_of_scope_types']) or '(none)'}\n"
            f"  Rate limit:           {(str(rl) + ' req/s') if rl else 'none stated'}"
            + (f", {roe['max_concurrent']} concurrent" if roe.get("max_concurrent") else "")
            + (("\n  Remember:             " + "  |  ".join(roe["rules"])) if roe.get("rules") else "")
            + "\n\nNow run a hunt on an in-scope target — out-of-scope targets are refused, out-of-scope "
              "finding types are filtered, and the rate limit is applied to the scanners."
        )
        return {"success": True, "message": msg, "data": {"scope": scope, "roe": roe}}

    def scope_status(self) -> dict:
        """Show the current bug-bounty scope (data/scope.json) so you can confirm what
        the tool will and won't touch."""
        scope = _load_scope()
        if not scope:
            return {"success": True, "data": {"scope": {}},
                    "message": "No data/scope.json — every target is treated as 'unknown' (advisory only). "
                               "Create it: {\"in_scope\":[\"*.acme.com\"],\"out_of_scope\":[\"admin.acme.com\"]}"}
        ins = scope.get("in_scope", []); outs = scope.get("out_of_scope", [])
        msg = (f"Scope loaded: {len(ins)} in-scope, {len(outs)} out-of-scope rules.\n"
               f"  IN:  {', '.join(ins) or '(none)'}\n"
               f"  OUT: {', '.join(outs) or '(none)'}\n"
               "Most-specific-wins; out-of-scope targets are refused (use force/--force to override).")
        return {"success": True, "message": msg, "data": {"scope": scope}}

    # =====================================
    # RUN
    # =====================================
    # ── F4 execution-timeline surface (parity; recon drives these via the CLI too) ──
    def timeline_show(self, run_id: str = "") -> dict:
        """No run_id -> list recent runs; a run_id -> the platform-feel viewer for that run."""
        from core import timeline
        if not run_id:
            return {"success": True, "message": timeline.render_list(),
                    "data": {"runs": timeline.list_runs()}}
        view = timeline.render(run_id)
        if not view:
            return {"success": False, "message": f"No recorded run '{run_id}'.", "data": {}}
        return {"success": True, "message": view, "data": timeline.load(run_id) or {}}

    def make_package(self, run_id: str = "") -> dict:
        """Zip a recorded run (timeline + artifacts + report + evidence) into a submission.
        Read-only assembly. Defaults to the most recent run."""
        from core import timeline, package
        run_id = run_id or (timeline.list_runs()[0] if timeline.list_runs() else "")
        if not run_id:
            return {"success": False, "message": "No recorded runs to package yet.", "data": {}}
        return package.build_package(run_id)

    def replay_run(self, run_id: str = "", step: str = "") -> dict:
        """Rerun a recorded run (full, or a step: recon|probe). NOTE: launches an ACTIVE
        scan against the recorded target."""
        from core import replay
        return replay.replay(run_id, step or None)

    def run(
        self,
        input_text: str,
        action: str = None,
        parameters: dict = None
    ) -> dict:

        try:
            parameters = parameters or {}

            if not action:
                return {"success": False, "message": "No Ultron action specified.", "data": {}}

            target = parameters.get("target", "")

            if action == "nmap_scan":
                return self.nmap_scan(target, parameters.get("scan_type", "basic"))

            elif action == "subfinder":
                return self.subfinder(target)

            elif action == "httpx_probe":
                return self.httpx_probe(target)

            elif action == "nuclei_scan":
                return self.nuclei_scan(target, parameters.get("severity", "medium,high,critical"))

            elif action == "full_recon":
                return self.full_recon(target, parameters.get("force", False),
                                       parameters.get("discover", False))

            elif action == "full_pipeline":
                return self.full_pipeline(target, discover=parameters.get("discover", False))

            elif action == "bug_bounty":
                return self.bug_bounty(target, parameters.get("validate", True),
                                       parameters.get("force", False),
                                       discover=parameters.get("discover", False))

            elif action == "katana_crawl":
                return self.katana_crawl(target, parameters.get("depth", 3))

            elif action == "content_discovery":
                return self.content_discovery(target, parameters.get("wordlist", ""))

            elif action == "spa_crawl":
                return self.spa_crawl(target)

            elif action == "crawl_site":
                return self.crawl_site(target)

            elif action == "take_screenshot":
                return self.take_screenshot(target)

            elif action == "find_exploits":
                return self.find_exploits(parameters.get("cve_id", target))

            elif action == "search_cve":
                return self.search_cve(
                    parameters.get("keyword", target),
                    parameters.get("severity", ""),
                    parameters.get("days_back", 7),
                )

            elif action == "cve_track":
                return self.cve_track(parameters.get("cve_id", target))

            elif action == "cve_list":
                return self.cve_list()

            elif action == "cve_check":
                return self.cve_check(parameters.get("cve_id"))

            elif action == "cve_untrack":
                return self.cve_untrack(parameters.get("cve_id", target))

            elif action == "correlate":
                return self.correlate()

            elif action == "ht_preflight":
                return self.ht_preflight()

            elif action == "ht_search":
                return self.ht_search(parameters.get("query", target),
                                      parameters.get("category", ""))

            elif action == "ht_run":
                return self.ht_run(parameters.get("tool_id", ""),
                                   parameters.get("args", ""),
                                   parameters.get("allow_extended", False))

            elif action == "system_health":
                return self.system_health()

            elif action == "target_profile":
                from core import target_profiles
                return target_profiles.summary(parameters.get("target", target))

            elif action == "list_targets":
                from core import target_profiles
                return target_profiles.list_targets()

            elif action == "scope_status":
                return self.scope_status()

            elif action == "watch_target":
                return self.watch_target(parameters.get("target", target))

            elif action == "unwatch_target":
                return self.unwatch_target(parameters.get("target", target))

            elif action == "list_watched":
                return self.list_watched()

            elif action == "monitor_targets":
                return self.monitor_targets()

            elif action == "setup_scope":
                return self.setup_scope(parameters.get("text", ""))

            elif action == "profile_note":
                from core import target_profiles
                return target_profiles.add_note(parameters.get("target", target),
                                                parameters.get("note", ""))

            elif action == "ingest_burp":
                return self.ingest_burp(parameters.get("path", target))

            elif action == "github_hunt":
                from core import github_hunt
                return github_hunt.hunt(parameters.get("org", target))

            elif action == "collect_evidence":
                return self.collect_evidence(parameters.get("url", target),
                                             parameters.get("label", ""))

            elif action == "playbook_recall":
                return self.playbook_recall(parameters.get("query", target) or input_text,
                                            parameters.get("stack", ""))

            elif action == "remember_technique":
                return self.remember_technique(parameters.get("text", target) or input_text,
                                               parameters.get("vuln_class", "manual"),
                                               parameters.get("stack", ""))

            elif action == "ingest_writeup":
                return self.ingest_writeup(parameters.get("url", target) or input_text)

            elif action == "ingest_feed":
                return self.ingest_feed(parameters.get("url", target) or input_text)

            elif action == "session_set":
                return self.session_set(parameters.get("name", ""), parameters.get("cookie", ""),
                                        parameters.get("bearer", ""), parameters.get("role", "user"))
            elif action == "session_list":
                return self.session_list()
            elif action == "replay_as":
                return self.replay_as(parameters.get("name", ""), parameters.get("url", target),
                                      parameters.get("method", "GET"), parameters.get("body", ""))
            elif action == "idor_check":
                return self.idor_check(parameters.get("url", target), parameters.get("owner", "userA"),
                                       parameters.get("attacker", "userB"))
            elif action == "write_bola_check":
                return self.write_bola_check(parameters.get("url", target),
                                             parameters.get("field", "email"),
                                             parameters.get("owner", "userA"),
                                             parameters.get("attacker", "userB"),
                                             parameters.get("method", "PUT"),
                                             parameters.get("verify_url", ""))
            elif action == "graphql_hunt":
                return self.graphql_hunt(parameters.get("url", target), parameters.get("as_user", ""))

            elif action == "target_dorks":
                return self.target_dorks(parameters.get("target", target))

            elif action == "find_programs":
                return self.find_programs(parameters.get("region", ""))

            elif action == "kb_methodology":
                from core import security_kb
                return security_kb.methodology(parameters.get("query", target) or input_text)

            elif action == "kb_wordlist":
                from core import security_kb
                return security_kb.wordlist_path(parameters.get("kind", target))

            elif action == "defensive_scan":
                return self.defensive_scan()

            elif action == "set_security_baseline":
                return self.set_security_baseline()

            elif action == "file_scan":
                return self.file_scan(parameters.get("path", ""))

            elif action == "vt_scan":
                return self.vt_scan(parameters.get("target", target) or parameters.get("path", ""))

            elif action == "threat_intel":
                return self.threat_intel(parameters.get("ioc", target))

            elif action == "log_check":
                return self.log_check()

            elif action == "export_html":
                return self.export_html()

            elif action == "dns_lookup":
                return self.dns_lookup(parameters.get("target", target))

            elif action == "hash_target":
                return self.hash_target(
                    parameters.get("target", target),
                    parameters.get("algorithm", "sha256")
                )

            # Legacy
            elif action == "scan_localhost":
                return self.nmap_scan("127.0.0.1", "basic")

            elif action == "security_summary":
                reports = parameters.get("reports", [])
                text = " ".join(r.get("message", "") for r in reports).lower()
                score = sum([
                    "open port" in text,
                    "suspicious" in text * 2,
                    "error" in text
                ])
                overall = (
                    "System looks safe." if score == 0
                    else "Minor risks detected." if score <= 2
                    else "Security concerns detected. Investigate."
                )
                return {"success": True, "message": overall, "data": {"risk_score": score}}

            return {
                "success": False,
                "message": f"Unsupported Ultron action: {action}",
                "data": {}
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"Ultron error: {str(e)}",
                "data": {}
            }


ultron_agent = UltronAgent()
