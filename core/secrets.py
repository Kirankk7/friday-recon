"""
Secrets / exposure detection (v1.3 A4) — deterministic, precision-first.

Two deterministic scans a crawler feeds into:
  1. find_secrets(text)   — hard-coded API keys/tokens/private-keys in crawled JS/HTML. Only DISTINCTIVE-
     prefix patterns (AKIA…, AIza…, ghp_…, xox…, sk_live_…, -----BEGIN…PRIVATE KEY-----). Generic
     "api_key=…" / 40-char-blobs are EXCLUDED — they false-match constantly and Friday doesn't guess.
  2. find_endpoints(text) — path strings ("/api/…") baked into JS = attack surface the crawler missed.
Plus SENSITIVE_PATHS + file_signature() for the exposed-file probe (.git/.env/.DS_Store) the caller GETs.

Pure functions, no network, no dependency — the ultron method does the HTTP and assembles findings.
Authorized targets only.
"""
import re

# (name, compiled regex) — every pattern has a service-specific prefix so a hit is high-confidence.
_SECRET_PATTERNS = [
    ("AWS access key id",        re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS session/temp key",     re.compile(r"ASIA[0-9A-Z]{16}")),
    ("Google API key",           re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Google OAuth client id",   re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
    ("Slack token",              re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Slack webhook",            re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),
    ("Stripe live secret key",   re.compile(r"[sr]k_live_[0-9a-zA-Z]{20,40}")),
    ("GitHub token",             re.compile(r"gh[opsu]_[0-9A-Za-z]{36,}")),
    ("GitHub fine-grained PAT",  re.compile(r"github_pat_[0-9A-Za-z_]{60,}")),
    ("SendGrid API key",         re.compile(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}")),
    ("Twilio API/account SID",   re.compile(r"(?:SK|AC)[0-9a-fA-F]{32}")),
    ("Mailgun key",              re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("Firebase cloud-msg key",   re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}")),
    ("Private key block",        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Hard-coded JWT",           re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

_ENDPOINT_RE = re.compile(r"""["'](/[a-zA-Z0-9_][a-zA-Z0-9_./?=&%-]{2,120})["']""")

# Sensitive files the caller GETs on the base host; (path, [content signatures that confirm exposure]).
SENSITIVE_PATHS = [
    (".git/config",   ["[core]", "repositoryformatversion"]),
    (".git/HEAD",     ["ref: refs/"]),
    (".env",          ["=", "APP_", "DB_", "SECRET", "KEY", "PASSWORD"]),
    (".DS_Store",     ["Bud1", "\x00\x00\x00\x01Bud1"]),
    (".svn/entries",  ["dir", "svn:"]),
    ("config.json.bak", ["{"]),
    ("backup.sql",    ["INSERT INTO", "CREATE TABLE"]),
]


def find_secrets(text: str):
    """[(name, matched-substring)] for hard-coded secrets in `text`. De-duped by match."""
    out, seen = [], set()
    for name, rx in _SECRET_PATTERNS:
        for m in rx.findall(text or ""):
            frag = m if isinstance(m, str) else (m[0] if m else "")
            if frag and frag not in seen:
                seen.add(frag)
                out.append((name, frag))
    return out


def find_endpoints(text: str):
    """Distinct path strings baked into JS/HTML — attack surface the crawler may have missed."""
    return sorted({m for m in _ENDPOINT_RE.findall(text or "")
                   if not m.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ico"))})


def file_signature(path: str, body: str) -> bool:
    """True if `body` matches a known signature for sensitive `path` (confirms real exposure, not a 200 SPA)."""
    for p, sigs in SENSITIVE_PATHS:
        if path.endswith(p):
            return any(s in (body or "") for s in sigs)
    return False
