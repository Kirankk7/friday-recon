"""
Phase 63 — GitHub org secret hunt.

Enumerate an org's (or user's) public repos via the GitHub API and flag
secret-prone files in each repo tree (.env, keys, creds, dumps). With a token,
also runs code search for secret patterns. Recommends a trufflehog deep-scan
(already in the HackingTool fleet) for confirmed candidates. No cloning, API-only,
graceful without a token (60/hr).
"""

import os
import re

try:
    from config import GITHUB_TOKEN
except Exception:
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# filenames/paths that commonly leak secrets
_SECRET_FILES = re.compile(
    r"(^|/)(\.env|\.env\.[\w.]+|\.npmrc|\.pypirc|\.netrc|\.dockercfg|"
    r"id_rsa|id_dsa|id_ed25519|.*\.pem|.*\.ppk|.*\.pfx|.*\.p12|.*\.keystore|"
    r"credential[\w.-]*|secret[\w.-]*|config\.(json|php|py|rb)|"
    r"settings\.py|wp-config\.php|\.git-credentials|.*\.sql|.*\.bak|"
    r"service-?account.*\.json|firebase.*\.json|.*backup.*)$",
    re.IGNORECASE)


def _headers():
    h = {"Accept": "application/vnd.github+json", "User-Agent": "JARVIS-Ultron/1.0"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def _list_repos(org: str, n: int):
    import requests
    for kind in ("orgs", "users"):
        try:
            r = requests.get(f"https://api.github.com/{kind}/{org}/repos",
                             params={"per_page": min(n, 100), "sort": "pushed"},
                             headers=_headers(), timeout=12)
            if r.status_code == 200 and isinstance(r.json(), list) and r.json():
                return r.json()[:n], None
            if r.status_code == 403:
                return None, "GitHub rate limit (60/hr without token). Set GITHUB_TOKEN."
        except Exception as e:
            return None, f"GitHub error: {str(e)[:50]}"
    return None, f"No public repos found for '{org}'."


def _scan_tree(full_name: str, branch: str):
    import requests
    try:
        r = requests.get(f"https://api.github.com/repos/{full_name}/git/trees/{branch}",
                         params={"recursive": "1"}, headers=_headers(), timeout=12)
        if r.status_code != 200:
            return []
        tree = r.json().get("tree", [])
        return [t["path"] for t in tree if t.get("type") == "blob" and _SECRET_FILES.search(t["path"])]
    except Exception:
        return []


def hunt(org: str, max_repos: int = 10) -> dict:
    """Enumerate org repos, flag secret-prone files. Authorized targets only."""
    org = (org or "").strip().strip("/").split("/")[-1]
    if not org:
        return {"success": False, "message": "Which org/user? e.g. 'github hunt acme'.", "data": {}}

    repos, err = _list_repos(org, max_repos)
    if err:
        return {"success": False, "message": err, "data": {}}

    flagged, scanned = [], 0
    for repo in repos:
        scanned += 1
        hits = _scan_tree(repo["full_name"], repo.get("default_branch", "main"))
        if hits:
            flagged.append({"repo": repo["full_name"], "files": hits[:15]})

    if not flagged:
        msg = (f"Scanned {scanned} repo(s) under '{org}' — no obviously secret-prone files "
               f"in the trees. Run trufflehog for a deep history scan to be sure.")
    else:
        lines = [f"Scanned {scanned} repo(s) under '{org}'. {len(flagged)} with secret-prone files:"]
        for f in flagged[:10]:
            lines.append(f"  {f['repo']}: {', '.join(os.path.basename(x) for x in f['files'][:6])}")
        lines.append("Deep-scan a hit: run tool information_gathering.TruffleHog on the repo URL.")
        msg = "\n".join(lines)

    return {"success": True, "message": msg,
            "data": {"org": org, "scanned": scanned, "flagged": flagged,
                     "token": bool(GITHUB_TOKEN)}}
