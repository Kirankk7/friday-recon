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


def _resolve_scheme(target: str) -> str:
    """Pick a scheme that actually responds for a bare host.

    Bug-bounty/recon used to hardcode https:// — http-only targets (e.g. many
    test/legacy hosts on port 80) then silently returned nothing, and the LLM
    rationalised the empty result as 'low risk'. This probes https then http and
    returns the first that answers (any HTTP status = reachable), defaulting to
    https. Already-schemed targets pass through untouched.
    """
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


def _cve_product_keywords(entry: dict) -> set:
    """Extract product-name keywords from a CVE watchlist entry's affected CPE list + description."""
    kws = set()
    for a in entry.get("affected", []):
        # "vendor:product version" → take product, drop version
        vp = a.split()[0] if a else ""
        parts = vp.split(":")
        if parts:
            prod = parts[-1].replace("_", " ").strip().lower()
            if prod and prod != "*":
                kws.add(prod)
                for tok in prod.split():
                    if len(tok) > 2:
                        kws.add(tok)
    # Fallback: mine common product words from description if no CPE
    if not kws:
        desc = (entry.get("description") or "").lower()
        for prod in ("openssh", "ssh", "nginx", "apache", "http", "openssl",
                     "mysql", "postgres", "redis", "mongodb", "ftp", "smb",
                     "rdp", "tomcat", "jenkins", "log4j", "windows", "linux"):
            if prod in desc:
                kws.add(prod)
    return kws


def _service_tokens(services: list) -> set:
    """Service-name tokens from scan history port entries ('22/tcp ssh' → {'ssh'})."""
    toks = set()
    for s in services:
        parts = s.split()  # "22/tcp ssh"
        for p in parts[1:]:  # skip port/proto
            p = p.strip().lower()
            if len(p) > 2:
                toks.add(p)
    return toks


def _match_products(cve_kws: set, svc_toks: set) -> list:
    """Bidirectional substring match (min len 3) between CVE products and host services."""
    hits = set()
    for ct in cve_kws:
        for st in svc_toks:
            if len(ct) >= 3 and len(st) >= 3 and (ct in st or st in ct):
                hits.add(st)
    return sorted(hits)


# ── Bug-bounty workflow (Phase 54) ────────────────────────────────────────────
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


# Error-based SQLi response signatures (DB engine error strings leaking into the page).
_SQL_ERROR_SIGNS = re.compile(
    r"sql syntax|mysql_fetch|you have an error in your sql|ORA-\d{5}|"
    r"microsoft ole db|unclosed quotation mark|sqlite_error|sqlstate|"
    r"npgsql|psqlexception|pg::syntaxerror|syntax error at or near|"
    r"warning:\s*mysql|valid mysql result|sqlexception|incorrect syntax near|"
    r"odbc.*driver|microsoft jet database",
    re.IGNORECASE)
# Unique-ish token for reflected-XSS detection (with angle brackets to prove no encoding).
_XSS_MARKER = "jvz9xqk7z"


def _parse_nuclei_findings(raw: str) -> list:
    """Parse nuclei output lines → structured findings.
    Nuclei format: [template-id] [protocol] [severity] url [extra]"""
    findings = []
    if not raw:
        return findings
    import re as _re
    for line in raw.splitlines():
        line = line.strip()
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


def _md_to_html(md: str, title: str) -> str:
    """Minimal Markdown → HTML converter for reports (no external deps)."""
    import re as _re
    lines = md.splitlines()
    html_lines = [
        "<!DOCTYPE html><html><head>",
        f"<meta charset='utf-8'><title>{title}</title>",
        "<style>body{font-family:monospace;background:#0a0a1a;color:#00d4ff;padding:2em;max-width:900px;margin:auto}",
        "h1,h2,h3{color:#ff9600}pre{background:#111;padding:1em;overflow:auto;color:#aaffaa}",
        "hr{border-color:#333}strong{color:#fff}</style></head><body>",
    ]
    in_pre = False
    for line in lines:
        if line.startswith("```"):
            if in_pre:
                html_lines.append("</pre>")
                in_pre = False
            else:
                html_lines.append("<pre>")
                in_pre = True
            continue
        if in_pre:
            html_lines.append(line)
            continue
        if line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("---"):
            html_lines.append("<hr>")
        elif line.startswith("**") and line.endswith("**"):
            html_lines.append(f"<strong>{line[2:-2]}</strong><br>")
        elif line.strip():
            # Bold inline
            line = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
            html_lines.append(f"<p>{line}</p>")
    html_lines.append("</body></html>")
    return "\n".join(html_lines)


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
            desktop = os.path.join(
                os.path.expanduser("~"), "Desktop"
            )
            date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = (
                name.lower()
                .replace(" ", "_")
                .replace("/", "_")
                .replace(":", "")
                .replace(".", "_")
            )
            filename = f"ultron_{safe_name}_{date_str}.md"
            filepath = os.path.join(desktop, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

            # Store for HTML export
            self._last_report_md = content
            self._last_report_name = safe_name

            return filepath
        except Exception:
            return None

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
            html = _md_to_html(self._last_report_md, f"Ultron Report — {self._last_report_name}")
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
            ["httpx", "-u", target, "-title", "-status-code", "-tech-detect", "-silent"],
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
    def nuclei_scan(self, target: str, severity: str = "medium,high,critical") -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Nuclei scan: {target} (severity: {severity})")

        output = run_cmd(
            ["nuclei", "-u", target, "-severity", severity, "-silent"],
            timeout=180
        )

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
        import urllib.request
        import urllib.parse
        import json as _json
        import re as _re

        # Normalize CVE ID
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        if not _re.match(r"CVE-\d{4}-\d+", cve_id):
            return {"success": False, "message": f"Invalid CVE format: '{cve_id}'. Expected CVE-YYYY-NNNN.", "data": {}}

        print(f"[ULTRON] Finding exploits for {cve_id}")

        pocs = []
        nvd_info = {}

        # ── NVD API — description + CVSS + CWE + affected products ──
        try:
            from config import NVD_API_KEY as _nvd_key
        except Exception:
            _nvd_key = ""
        try:
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            _nvd_hdrs = {"User-Agent": "JARVIS-Ultron/1.0"}
            if _nvd_key:
                _nvd_hdrs["apiKey"] = _nvd_key
            req = urllib.request.Request(nvd_url, headers=_nvd_hdrs)
            throttle("nvd")   # space NVD calls to avoid 429
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = _json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                metrics = cve_data.get("metrics", {})
                cvss_score, cvss_sev, vector = None, None, None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cd = metrics[key][0].get("cvssData", {})
                        cvss_score = cd.get("baseScore")
                        cvss_sev = cd.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                        vector = cd.get("vectorString")
                        break
                # CWE extraction
                cwes = []
                for w in cve_data.get("weaknesses", []):
                    for d in w.get("description", []):
                        if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                            cwes.append(d["value"])
                # Affected products from CPE
                affected = []
                for cfg in cve_data.get("configurations", []):
                    for node in cfg.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            if cpe.get("vulnerable"):
                                parts = cpe.get("criteria", "").split(":")
                                if len(parts) >= 5:
                                    vendor = parts[3]
                                    product = parts[4]
                                    version = parts[5] if len(parts) > 5 else "*"
                                    label = f"{vendor}:{product}" + (f" {version}" if version != "*" else "")
                                    if label not in affected:
                                        affected.append(label)
                nvd_info = {
                    "description": desc[:300],
                    "cvss_score": cvss_score,
                    "severity": cvss_sev,
                    "vector": vector,
                    "cwes": cwes[:3],
                    "affected": affected[:8],
                }
        except Exception as e:
            print(f"[ULTRON] NVD lookup failed: {e}")

        # ── GitHub Search — PoC repos ──
        try:
            q = urllib.parse.quote(cve_id)
            gh_url = f"https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=10"
            req = urllib.request.Request(gh_url, headers={
                "User-Agent": "JARVIS-Ultron/1.0",
                "Accept": "application/vnd.github+json"
            })
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = _json.loads(resp.read().decode())
            for item in data.get("items", [])[:8]:
                pocs.append({
                    "source": "GitHub",
                    "name": item["full_name"],
                    "url": item["html_url"],
                    "stars": item["stargazers_count"],
                    "desc": (item.get("description") or "")[:100]
                })
        except Exception as e:
            print(f"[ULTRON] GitHub search failed: {e}")

        # Also search GitHub code for CVE references
        try:
            q = urllib.parse.quote(cve_id)
            gh_code_url = f"https://api.github.com/search/repositories?q={q}+exploit+poc&sort=stars&order=desc&per_page=5"
            req = urllib.request.Request(gh_code_url, headers={
                "User-Agent": "JARVIS-Ultron/1.0",
                "Accept": "application/vnd.github+json"
            })
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = _json.loads(resp.read().decode())
            existing_urls = {p["url"] for p in pocs}
            for item in data.get("items", [])[:5]:
                if item["html_url"] not in existing_urls:
                    pocs.append({
                        "source": "GitHub",
                        "name": item["full_name"],
                        "url": item["html_url"],
                        "stars": item["stargazers_count"],
                        "desc": (item.get("description") or "")[:100]
                    })
        except Exception as e:
            print(f"[ULTRON] GitHub PoC search failed: {e}")

        # ── Exploit-DB — scrape search results ──
        try:
            import re as _re2
            cve_num = cve_id.replace("CVE-", "")
            edb_url = f"https://www.exploit-db.com/search?cve={cve_num}"
            req = urllib.request.Request(edb_url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml"
            })
            with urllib.request.urlopen(req, timeout=12) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            exploit_ids = list(dict.fromkeys(_re2.findall(r'/exploits/(\d+)', html)))
            for eid in exploit_ids[:6]:
                pocs.append({
                    "source": "Exploit-DB",
                    "name": f"EDB-{eid}",
                    "url": f"https://www.exploit-db.com/exploits/{eid}",
                    "stars": 0,
                    "desc": f"Exploit-DB entry for {cve_id}"
                })
        except Exception as e:
            print(f"[ULTRON] Exploit-DB search failed: {e}")

        # ── Build voice response ──
        lines = [f"Exploit search results for {cve_id}:"]

        if nvd_info:
            sev = nvd_info.get("severity") or "Unknown"
            score = nvd_info.get("cvss_score") or "?"
            lines.append(f"NVD: CVSS {score} ({sev}). {nvd_info.get('description', '')[:200]}")
            if nvd_info.get("vector"):
                lines.append(f"     Vector: {nvd_info['vector']}")
            if nvd_info.get("cwes"):
                lines.append(f"     CWE: {', '.join(nvd_info['cwes'])}")
            if nvd_info.get("affected"):
                lines.append(f"     Affected: {', '.join(nvd_info['affected'][:5])}")

        gh_pocs = [p for p in pocs if p["source"] == "GitHub"]
        edb_pocs = [p for p in pocs if p["source"] == "Exploit-DB"]

        if gh_pocs:
            lines.append(f"\nGitHub PoCs ({len(gh_pocs)}):")
            for p in sorted(gh_pocs, key=lambda x: -x["stars"])[:6]:
                lines.append(f"  ★{p['stars']}  {p['name']}")
                lines.append(f"         {p['url']}")
                if p["desc"]:
                    lines.append(f"         {p['desc']}")

        if edb_pocs:
            lines.append(f"\nExploit-DB ({len(edb_pocs)}):")
            for p in edb_pocs[:5]:
                lines.append(f"  {p['name']}: {p['url']}")

        if not pocs and not nvd_info:
            return {
                "success": True,
                "message": f"No public PoCs or NVD data found for {cve_id}. May be too new or not yet public.",
                "data": {"cve": cve_id, "pocs": [], "nvd": {}}
            }

        message = "\n".join(lines)

        # Save report to Desktop
        report = f"# Exploit PoC Search: {cve_id}\n\nGenerated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n{message}"
        self.save_report(f"exploits_{cve_id.replace('-', '_')}", report)

        total = len(pocs)
        voice = f"Found {total} PoC {'entry' if total == 1 else 'entries'} for {cve_id}. "
        if nvd_info.get("cvss_score"):
            voice += f"CVSS score {nvd_info['cvss_score']}, {nvd_info.get('severity', 'unknown')} severity. "
        if gh_pocs:
            top = sorted(gh_pocs, key=lambda x: -x["stars"])[0]
            voice += f"Top GitHub PoC: {top['name']} with {top['stars']} stars."

        return {
            "success": True,
            "message": voice,
            "data": {
                "cve": cve_id,
                "pocs": pocs,
                "nvd": nvd_info,
                "total": total,
                "full_output": message
            }
        }

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

            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = target.replace(".", "_").replace("/", "_").replace(":", "")[:30]
            filename = f"screenshot_{safe}_{date_str}.png"
            filepath = os.path.join(desktop, filename)

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
                "message": f"Screenshot saved to Desktop: {filename}",
                "data": {"path": filepath, "url": url}
            }

        except ImportError:
            return {"success": False, "message": "Playwright not installed.", "data": {}}
        except Exception as e:
            return {"success": False, "message": f"Screenshot failed: {e}", "data": {}}

    # =====================================
    # FULL PIPELINE (Phase 24)
    # Nmap → Subfinder → Httpx → Nuclei → Katana → Screenshot
    # =====================================
    def full_pipeline(self, target: str) -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Full pipeline: {target}")

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

        # ── Stage 3: Httpx ── (resolve http/https, don't force https)
        print("[ULTRON] Stage 3/5: Httpx...")
        base_url = _resolve_scheme(target)
        httpx_r = self.httpx_probe(base_url)
        sections["httpx"] = httpx_r.get("message", "Failed.")
        reachable = bool(httpx_r.get("data", {}).get("raw", "").strip())

        # ── Stage 4: Nuclei ──
        print("[ULTRON] Stage 4/5: Nuclei...")
        nuclei_r = self.nuclei_scan(base_url)
        sections["nuclei"] = nuclei_r.get("data", {}).get("raw") or nuclei_r.get("message", "No findings.")

        # ── Stage 5: Katana ──
        print("[ULTRON] Stage 5/5: Katana + Screenshot...")
        katana_r = self.katana_crawl(target)
        sections["katana"] = katana_r.get("message", "Skipped.")
        urls = katana_r.get("data", {}).get("urls", [])

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
**Pipeline:** Nmap → Subfinder → Httpx → Nuclei → Katana → Screenshot

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
        """Parse a Burp HTTP-history XML export → endpoint inventory → target profile."""
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

    # =====================================
    # VALIDATION GATE (Phase 60 — adapted from shuvonsec/claude-bug-bounty)
    # =====================================
    # Never-submit blacklist: template-id fragments that are noise / informational
    # and get auto-closed as N/A on bug-bounty platforms. Findings matching these
    # are dropped from the report regardless of severity.
    _NEVER_SUBMIT = (
        "ssl", "tls-version", "tech-detect", "tech-stack", "fingerprint",
        "missing-header", "security-header", "http-missing", "x-frame",
        "version-disclosure", "version-detect", "waf-detect", "wafw00f",
        "favicon", "robots-txt", "sitemap", "default-page", "dns-",
        "dmarc", "spf-", "cookie-without", "cors-misconfig-detect",
        "metatag", "openapi", "swagger-api", "weak-cipher",
    )
    # severity -> bug-bounty payout/priority tier (HackerOne-style)
    _PAYOUT_TIER = {
        "critical": "P1 (Critical)", "high": "P2 (High)", "medium": "P3 (Medium)",
        "low": "P4 (Low)", "info": "P5 (Informational)",
    }

    def _probe_injection(self, urls: list, max_urls: int = 30, max_params: int = 8) -> list:
        """Lightweight injection smell-test over crawled URLs that carry query params.

        For each param sends ONE benign probe — a single quote (error-based SQLi
        signal) and a reflected marker (XSS) — and flags CANDIDATES, not exploits.
        Minimal-proof by design: one extra request per param, hard-capped, no data
        pulled. Findings carry validated=True (signal observed directly) + evidence
        + repro so the quality gate and report can use them. Authorized targets only.
        """
        import time
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        try:
            import requests
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
                base_status, base_len = None, None
                try:
                    b = requests.get(u, timeout=8)
                    base_status, base_len = b.status_code, len(b.text or "")
                except Exception:
                    pass
                for i, (k, v) in enumerate(qs[:max_params]):
                    sig = (parts.scheme, parts.netloc, parts.path, k)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    # --- SQLi probe (single quote): error-string OR response anomaly ---
                    try:
                        q = qs.copy(); q[i] = (k, (v or "") + "'")
                        purl = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
                        time.sleep(0.1)
                        r = requests.get(purl, timeout=8)
                        body = r.text or ""
                        m = _SQL_ERROR_SIGNS.search(body)
                        # anomaly: baseline was a healthy 200-with-body, but the quote
                        # flips it to a server error / empty body = query broke (classic SQLi).
                        anomaly = (base_status == 200 and (base_len or 0) > 200
                                   and (r.status_code >= 500 or len(body) == 0))
                        if m or anomaly:
                            ev = (f"DB error '{m.group(0)}' surfaced after injecting a single quote into param '{k}'."
                                  if m else
                                  f"Injecting a single quote into param '{k}' changed the response from "
                                  f"HTTP 200/{base_len}b to HTTP {r.status_code}/{len(body)}b — server-side "
                                  f"query error, a classic error-based SQLi signal.")
                            out.append({
                                "template": "sqli-error-based", "severity": "high",
                                "url": purl, "cve": None, "validated": True, "evidence": ev,
                                "repro": [f"Baseline: GET {u}  → HTTP {base_status}/{base_len}b",
                                          f"Inject:   GET {purl}",
                                          ("Observe the database error in the response body" if m
                                           else f"Observe the response break to HTTP {r.status_code}/{len(body)}b")],
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
                        r = requests.get(purl, timeout=8)
                        if marker in (r.text or ""):
                            out.append({
                                "template": "xss-reflected", "severity": "medium",
                                "url": purl, "cve": None, "validated": True,
                                "evidence": f"Input '{marker}' reflected unencoded in the response for param '{k}'.",
                                "repro": [f"Send: GET {purl}",
                                          f"Find the literal string '{marker}' (angle brackets intact) in the response",
                                          "Escalate to a script payload only under authorized manual testing"],
                            })
                    except Exception:
                        pass
            except Exception:
                continue
        if out:
            print(f"[ULTRON] injection smell-test flagged {len(out)} candidate(s) "
                  f"across {tested} parameterized endpoint(s).")
        return out

    def _validate_finding(self, f: dict, exploits_map: dict) -> dict:
        """
        7-question quality gate. Returns {report, score, tier, reasons, drop}.
        Kills weak/noise findings before they reach the report.
        """
        tmpl = (f.get("template") or "").lower()
        sev = (f.get("severity") or "info").lower()
        url = f.get("url") or ""
        cve = f.get("cve") or ""

        # hard blacklist → never submit
        if any(bad in tmpl for bad in self._NEVER_SUBMIT):
            return {"report": False, "score": 0, "tier": self._PAYOUT_TIER.get(sev, "P5"),
                    "reasons": [], "drop": "informational/noise class (never-submit list)"}

        reasons, score = [], 0
        # Q1 — meaningful severity (info-only alone is not worth a report)
        if sev in ("critical", "high", "medium", "low"):
            score += 1; reasons.append("has actionable severity")
        # Q2 — concrete location
        if url:
            score += 1; reasons.append("has a concrete URL/location")
        # Q3 — confirmed reachable (re-probe in validate stage)
        if f.get("validated") is True:
            score += 1; reasons.append("confirmed live on re-probe")
        # Q4 — exploitability (CVE with a known PoC/exploit)
        if cve and exploits_map.get(cve):
            score += 1; reasons.append("known public exploit/PoC exists")
        elif cve:
            score += 1; reasons.append("maps to a tracked CVE")
        # Q5 — real impact (not purely informational template)
        if sev in ("critical", "high", "medium"):
            score += 1; reasons.append("impact is more than informational")
        # Q6 — specificity (template names a real class, not a generic probe)
        if tmpl and "detect" not in tmpl and "panel" not in tmpl:
            score += 1; reasons.append("specific vulnerability, not a generic probe")
        # Q7 — severity-weighted confidence
        if sev in ("critical", "high") and (f.get("validated") is True or cve):
            score += 1; reasons.append("high severity AND corroborated")

        # report only if it clears the bar (>=3 of 7), or any confirmed crit/high
        report = score >= 3 or (sev in ("critical", "high") and f.get("validated") is True)
        return {"report": report, "score": score, "tier": self._PAYOUT_TIER.get(sev, "P5"),
                "reasons": reasons,
                "drop": None if report else f"failed quality gate ({score}/7)"}

    def _format_bb_report(self, target, findings, exploits_map, pipeline_data, validated):
        """Build a platform-ready PoC report.md — only gate-passed findings get
        a full write-up; filtered ones are listed transparently. Each finding
        carries a `_gate` dict from _validate_finding()."""
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        reportable = [f for f in findings if f.get("_gate", {}).get("report")]
        dropped = [f for f in findings if not f.get("_gate", {}).get("report")]
        reportable.sort(key=lambda f: _order.get(f.get("severity"), 9))

        tier_counts = {}
        for f in reportable:
            t = f["_gate"]["tier"]
            tier_counts[t] = tier_counts.get(t, 0) + 1
        tier_line = "  ·  ".join(f"{t}: {n}" for t, n in sorted(tier_counts.items())) or "none"

        lines = [
            f"# Bug Bounty Report — {target}",
            "",
            f"**Target:** {target}",
            f"**Generated:** {date_str}",
            "**Workflow:** Recon → Hunt → Validate → Quality Gate → Report (JARVIS Ultron)",
            "",
            "## Executive Summary",
            f"- Reportable findings: **{len(reportable)}** ({tier_line})",
            f"- Filtered by validation gate: {len(dropped)} (noise / unconfirmed / informational)",
            f"- Re-probe validation run: {'yes' if validated else 'no'}",
            "",
            "## Findings",
        ]

        if not reportable:
            lines.append("_No findings cleared the validation gate. Attack surface mapped below — "
                         "manual review recommended before submitting anything._")
        else:
            for i, f in enumerate(reportable, 1):
                g = f["_gate"]
                lines.append(f"\n### {i}. {f['template']}  —  {g['tier']}")
                lines.append(f"- **Severity:** {f['severity'].upper()}")
                if f.get("url"):
                    lines.append(f"- **Location:** {f['url']}")
                lines.append(f"- **Status:** {'Confirmed live' if f.get('validated') else 'Reported by scanner (unconfirmed)'}")
                lines.append(f"- **Confidence:** {g['score']}/7 quality checks passed")
                if f.get("evidence"):
                    lines.append(f"- **Evidence:** {f['evidence']}")
                if f.get("cve"):
                    lines.append(f"- **CVE:** {f['cve']}")
                    ex = exploits_map.get(f["cve"])
                    if ex:
                        lines.append(f"- **Public exploit/PoC:** {ex}")
                lines.append("- **Steps to reproduce:**")
                if f.get("repro"):
                    for n, step in enumerate(f["repro"], 1):
                        lines.append(f"  {n}. {step}")
                else:
                    lines.append(f"  1. Probe the endpoint: `httpx -u {f.get('url') or target}`")
                    lines.append(f"  2. Re-run the detection: `nuclei -u {f.get('url') or target} -id {f['template']}`")
                    lines.append("  3. Confirm the response matches the signature above.")
                lines.append(f"- **Impact:** {self._impact_line(f)}")
                lines.append("- **Remediation:** "
                             + ("Patch to a fixed version per the CVE advisory." if f.get("cve")
                                else "Apply the vendor fix / config hardening for this vulnerability class."))

        if dropped:
            lines += ["", "## Filtered by Validation Gate",
                      "_Surfaced by the scanner but withheld — would be closed as N/A / informational._"]
            for f in dropped[:25]:
                why = f.get("_gate", {}).get("drop", "low confidence")
                lines.append(f"- `{f['template']}` ({f['severity']}) — {why}")

        urls = pipeline_data.get("urls", [])
        lines += [
            "",
            "## Attack Surface",
            "- Subdomains: see recon output",
            f"- Crawled endpoints: {len(urls)}",
            "",
            "---",
            "*Generated by JARVIS Ultron — Bug Bounty Workflow w/ validation gate. Authorized targets only.*",
        ]
        return "\n".join(lines)

    def _impact_line(self, f: dict) -> str:
        sev = (f.get("severity") or "").lower()
        if f.get("cve"):
            return ("Exploitable known vulnerability — potential remote compromise; "
                    "prioritise immediately." if sev in ("critical", "high")
                    else "Known vulnerability present; exploitation feasible under conditions.")
        return {"critical": "Critical — likely full compromise of the affected component.",
                "high": "High — significant unauthorized access or data exposure likely.",
                "medium": "Medium — meaningful weakness, exploitation needs some conditions.",
                "low": "Low — limited direct impact; defence-in-depth concern.",
                }.get(sev, "Informational — minimal direct security impact.")

    def bug_bounty(self, target: str, validate: bool = True) -> dict:
        """Full bug-bounty hunt: recon pipeline → parse findings → CVE/exploit
        lookup → (validate) → structured PoC report. Authorized targets only."""
        if not target:
            return {"success": False, "message": "Target missing. Usage: 'bug bounty example.com'", "data": {}}

        # clean target (strip scheme)
        target = re.sub(r"^https?://", "", target.strip(), flags=re.IGNORECASE).rstrip("/")
        print(f"[ULTRON] Bug-bounty workflow on {target}")

        # ── Stage 1: Recon pipeline (nmap→subfinder→httpx→nuclei→katana) ──
        pipeline = self.full_pipeline(target)
        pdata = pipeline.get("data", {})
        nuclei_raw = pdata.get("sections", {}).get("nuclei", "")

        # ── Stage 2: Parse nuclei → structured findings ──
        findings = _parse_nuclei_findings(nuclei_raw)

        # ── Stage 2.5: Injection smell-test on crawled parameterized endpoints ──
        # nuclei detects known CVEs/misconfigs, not custom app-logic SQLi/XSS — so
        # actively probe the params katana found and surface injectable candidates.
        try:
            findings += self._probe_injection(pdata.get("urls", []))
        except Exception as e:
            print(f"[ULTRON] injection probe skipped: {e}")

        # ── Stage 3: CVE → exploit lookup (critical/high only, capped) ──
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

        # ── Stage 4.5: Quality gate — score each finding, drop noise/weak ones ──
        for f in findings:
            f["_gate"] = self._validate_finding(f, exploits_map)
        reportable = [f for f in findings if f["_gate"]["report"]]
        filtered = len(findings) - len(reportable)

        # ── Stage 5: Structured PoC report ──
        report = self._format_bb_report(target, findings, exploits_map, pdata, validated)
        saved = self.save_report(f"bugbounty_{target}", report)

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
            }
        }

    # =====================================
    # FULL RECON WORKFLOW
    # =====================================
    def full_recon(self, target: str) -> dict:

        if not target:
            return {"success": False, "message": "Target missing.", "data": {}}

        print(f"[ULTRON] Full recon: {target}")

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

    def defensive_scan(self) -> dict:
        """Compare the host against its baseline; flag new ports/processes + known-bad."""
        snap = self._defense_snapshot()

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
        if not new_ports and not new_procs and not bad_ports and not bad_procs:
            msg = "All clear, boss. Nothing new listening and no suspicious processes since your baseline."
        else:
            bits = []
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
                         "snapshot": snap}}

    def _defense_flags(self, bad_ports, bad_procs) -> str:
        parts = []
        if bad_ports:
            parts.append(f"known backdoor port(s) open: {', '.join(map(str, bad_ports))}")
        if bad_procs:
            parts.append(f"attacker-tool process(es) running: {', '.join(bad_procs)}")
        return " and ".join(parts)

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

        # Determine target type → VT v3 endpoint
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
            verdict = f"⚠ MALICIOUS — {mal}/{total} engines flagged {label}"
            if susp:
                verdict += f" ({susp} also suspicious)"
        elif susp > 0:
            verdict = f"⚠ SUSPICIOUS — {susp}/{total} engines flagged {label}, 0 malicious"
        else:
            verdict = f"✓ CLEAN — {label}: 0/{total} detections"

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
                updates.append(f"{cid}: PoC count changed {old_pocs} → {new_pocs} ({sign}{diff})")
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
    # CVE → ASSET CORRELATION (Phase 51 #9)
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

        lines = [f"⚠ {len(findings)} CVE-asset correlation(s) found:"]
        for f in findings:
            svc = ", ".join(f["services"])
            lines.append(
                f"  {f['cve_id']} ({f['severity']}, CVSS {f['cvss']}) → "
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
        """
        Search NVD for CVEs matching a keyword.
        severity: CRITICAL / HIGH / MEDIUM / LOW (empty = all)
        days_back: how many days back to search (0 = no date filter)
        """
        import urllib.request
        import urllib.parse
        import json as _json
        import datetime as _dt

        if not keyword:
            return {"success": False, "message": "Keyword required.", "data": {}}

        keyword = keyword.strip()

        try:
            from config import NVD_API_KEY as _nvd_key
        except Exception:
            _nvd_key = ""

        # Build URL params
        params = {"keywordSearch": keyword, "resultsPerPage": "15"}

        # Severity filter (NVD v2 uses cvssV3Severity param)
        sev_upper = severity.upper() if severity else ""
        if sev_upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            params["cvssV3Severity"] = sev_upper

        # Date filter
        if days_back and days_back > 0:
            start = _dt.datetime.utcnow() - _dt.timedelta(days=days_back)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
        print(f"[ULTRON] NVD search: {url}")

        try:
            hdrs = {"User-Agent": "JARVIS-Ultron/1.0"}
            if _nvd_key:
                hdrs["apiKey"] = _nvd_key
            req = urllib.request.Request(url, headers=hdrs)
            throttle("nvd")   # 50/30s (key) or 5/30s (no key) — space to avoid 429
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read().decode())
        except Exception as e:
            return {"success": False, "message": f"NVD API error: {e}", "data": {}}

        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            sev_note = f" {sev_upper}" if sev_upper else ""
            days_note = f" in last {days_back} days" if days_back else ""
            return {
                "success": True,
                "message": f"No{sev_note} CVEs found for '{keyword}'{days_note}.",
                "data": {"keyword": keyword, "total": 0, "results": []}
            }

        results = []
        lines = [f"Found {total} CVE{'s' if total != 1 else ''} for '{keyword}'" +
                 (f" ({sev_upper})" if sev_upper else "") +
                 (f" — last {days_back} days" if days_back else "") + ":"]

        for item in vulns[:10]:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "UNKNOWN")
            descs = cve_obj.get("descriptions", [])
            desc = next((d["value"] for d in descs if d["lang"] == "en"), "No description")
            metrics = cve_obj.get("metrics", {})
            score, sev_v = None, None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cd = metrics[key][0].get("cvssData", {})
                    score = cd.get("baseScore")
                    sev_v = cd.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                    break
            published = cve_obj.get("published", "")[:10]
            results.append({
                "id": cve_id,
                "score": score,
                "severity": sev_v,
                "published": published,
                "description": desc[:200],
            })
            score_str = f"CVSS {score} ({sev_v})" if score else "No CVSS"
            lines.append(f"  {cve_id}  [{score_str}]  {published}")
            lines.append(f"    {desc[:120]}")

        if total > 10:
            lines.append(f"  ...and {total - 10} more. Narrow with severity or date filter.")

        return {
            "success": True,
            "message": "\n".join(lines),
            "data": {
                "keyword": keyword,
                "severity_filter": sev_upper,
                "days_back": days_back,
                "total": total,
                "results": results,
            }
        }

    # =====================================
    # DNS LOOKUP (Phase 42)
    # =====================================
    def dns_lookup(self, target: str) -> dict:
        """Forward (hostname→IP) and reverse (IP→hostname) DNS. Pure stdlib socket."""
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
                    "message": f"Reverse DNS: {target} → {hostname}",
                    "data": {"ip": target, "hostname": hostname, "type": "reverse"}
                }
            else:
                _, _, ips = socket.gethostbyname_ex(target)
                ip_list = list(set(ips))[:5]
                ip_str = ", ".join(ip_list)
                return {
                    "success": True,
                    "message": f"DNS: {target} → {ip_str}",
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
                    "message": f"{tool_id} [{res.get('backend')}] ✓\n{summary}",
                    "data": res}
        if status in ("refused", "no_backend", "fallback"):
            return {"success": False, "message": res.get("message", status), "data": res}
        # error / timeout / unclassified
        err = res.get("message") or (res.get("stderr") or "")[:500] or status
        return {"success": False, "message": f"{tool_id} failed: {err}", "data": res}

    # =====================================
    # RUN
    # =====================================
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
                return self.full_recon(target)

            elif action == "full_pipeline":
                return self.full_pipeline(target)

            elif action == "bug_bounty":
                return self.bug_bounty(target, parameters.get("validate", True))

            elif action == "katana_crawl":
                return self.katana_crawl(target, parameters.get("depth", 3))

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
