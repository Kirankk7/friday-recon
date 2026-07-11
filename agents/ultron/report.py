"""
Ultron — report / analysis cluster (Phase B extraction, move-only).

The stateless report-synthesis unit lifted verbatim out of the ultron_agent god-class:
target fingerprinting (DB + features), the tailored test plan, per-finding impact lines,
the platform-ready PoC report, and the markdown->HTML renderer. All free functions calling
each other in-module (no `self`, no inheritance). The agent keeps thin delegators so its
public method API is unchanged.

External deps: stdlib only (re, datetime, urllib.parse) + lazy core.evidence / core.playbook.
"""
import datetime


# ── Test-planner knowledge (our own words; PortSwigger pages cited as references) ──
# DB-specific SQLi payloads per subtype — copy-paste ready for the confirmed param.
SQLI_PAYLOADS = {
    "mssql":      {"boolean": ("1 AND 1=1", "1 AND 1=2"), "time": "1; WAITFOR DELAY '0:0:5'--",
                   "version": "1 UNION SELECT @@version--"},
    "mysql":      {"boolean": ("1 AND 1=1", "1 AND 1=2"), "time": "1 AND SLEEP(5)-- -",
                   "version": "1 UNION SELECT @@version-- -"},
    "postgresql": {"boolean": ("1 AND 1=1", "1 AND 1=2"), "time": "1; SELECT pg_sleep(5)--",
                   "version": "1 UNION SELECT version()--"},
    "oracle":     {"boolean": ("1 AND 1=1", "1 AND 1=2"),
                   "time": "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)",
                   "version": "1 UNION SELECT banner FROM v$version--"},
    "sqlite":     {"boolean": ("1 AND 1=1", "1 AND 1=2"), "time": "1 AND 1=randomblob(100000000)",
                   "version": "1 UNION SELECT sqlite_version()--"},
    "generic":    {"boolean": ("1 AND 1=1", "1 AND 1=2"), "time": "(DB-specific — see references)",
                   "version": "1 UNION SELECT NULL--"},
}
TEST_REFS = {
    "sqli":     "https://portswigger.net/web-security/sql-injection",
    "xss":      "https://portswigger.net/web-security/cross-site-scripting",
    "access":   "https://portswigger.net/web-security/access-control",
    "auth":     "https://portswigger.net/web-security/authentication",
    "upload":   "https://portswigger.net/web-security/file-upload",
    "ssrf":     "https://portswigger.net/web-security/ssrf",
    "csrf":     "https://portswigger.net/web-security/csrf",
    "api":      "https://portswigger.net/web-security/api-testing",
}


def detect_db(httpx_txt: str, findings: list) -> str:
    """Best-effort DB fingerprint from tech-detect output + any SQLi error evidence."""
    s = (httpx_txt or "").lower() + " " + \
        " ".join((f.get("evidence", "") or "") for f in (findings or [])).lower()
    if any(x in s for x in ("ole db", "sql server", "mssql", "microsoft sql", "aspx", ".net", "iis")):
        return "mssql"
    if any(x in s for x in ("postgres", "psql", "pg::")):
        return "postgresql"
    if "ora-" in s or "oracle" in s:
        return "oracle"
    if "sqlite" in s:
        return "sqlite"
    if "mysql" in s or "php" in s:
        return "mysql"
    return "generic"


def detect_features(urls: list, sections: dict) -> dict:
    """Heuristic feature fingerprint from crawled paths — drives which tests are relevant."""
    paths = " ".join(urls or []).lower()
    return {
        "params":       any("?" in u for u in (urls or [])),
        "login":        any(w in paths for w in ("login", "signin", "sign-in", "account", "admin", "auth")),
        "stored_input": any(w in paths for w in ("comment", "post", "message", "feedback", "review", "guestbook")),
        "upload":       any(w in paths for w in ("upload", "attach", "import")),
        "api":          any(w in paths for w in ("/api", "/rest", "/v1", "/v2", "wp-json", "graphql")),
        "graphql":      "graphql" in paths,
        "redirect":     any(w in paths for w in ("redirect", "url=", "return=", "next=", "returnurl", "dest=")),
    }


def md_to_html(md: str, title: str) -> str:
    """Minimal Markdown -> HTML converter for reports (no external deps)."""
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


def impact_line(f: dict) -> str:
    """Data-driven impact for THIS finding: the canonical class-level impact (from the
    Evidence Object's map — one source of truth) + the concrete affected param/endpoint +
    a confidence qualifier from the gate. Deterministic, no over-claiming."""
    from core import evidence as _ev
    parts = [_ev.class_impact(f.get("template", ""))]   # class sentence, ends with '.'

    # concrete location — name the injected parameter, else the endpoint path
    loc = ""
    url = f.get("url", "") or ""
    try:
        from urllib.parse import urlsplit, parse_qsl
        u = urlsplit(url)
        q = parse_qsl(u.query)
        if q:
            loc = f" via parameter `{q[0][0]}`"
        elif u.path and u.path != "/":
            loc = f" at `{u.path}`"
    except Exception:
        pass
    if loc:
        parts.append(f"Affected{loc}.")
    if f.get("cve"):
        parts.append(f"Tracked as {f['cve']}.")

    qual = {"reproduced": "Reproduced directly on this target.",
            "supported": "Supported by a direct signal.",
            "candidate": "Candidate — needs manual confirmation."
            }.get((f.get("_gate", {}) or {}).get("confidence", ""), "")
    if qual:
        parts.append(qual)
    return " ".join(parts)


def dedup_findings(findings: list) -> list:
    """Collapse findings that share the same (template, host) into ONE representative (the
    highest-priority instance), recording the other affected endpoints under
    `_also_affected`. Same bug on N endpoints = 1 grouped finding, not N. Order-stable;
    never mutates the inputs. Findings on different templates/hosts pass through untouched."""
    from urllib.parse import urlsplit
    groups, order = {}, []
    for f in findings:
        host = urlsplit(f.get("url", "") or "").netloc
        key = (f.get("template", ""), host)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    out = []
    for key in order:
        g = groups[key]
        if len(g) == 1:
            out.append(g[0])
            continue
        rep = max(g, key=lambda x: x.get("_gate", {}).get("priority", 0))
        others = [x.get("url", "") for x in g if x is not rep and x.get("url")]
        rep = dict(rep)
        rep["_also_affected"] = others
        out.append(rep)
    return out


def build_test_plan(target: str, findings: list, pipeline_data: dict) -> list:
    """Tailored, honest test plan: fingerprint DB + features from recon, then per
    confirmed finding give subtype payloads + sqlmap, and per relevant feature give
    a manual to-do with method + PortSwigger reference. Skips irrelevant classes.
    Returns a list of markdown lines. Pure (no network) — easy to test."""
    sections = pipeline_data.get("sections", {}) or {}
    urls = pipeline_data.get("urls", []) or []
    httpx_txt = sections.get("httpx", "") or ""
    reportable = [f for f in findings if f.get("_gate", {}).get("report")]
    db = detect_db(httpx_txt, findings)
    feats = detect_features(urls, sections)

    def _param_of(url):
        from urllib.parse import urlsplit, parse_qsl
        q = parse_qsl(urlsplit(url).query)
        return q[0][0] if q else "param"

    L = ["", "## Test Plan — what to check on this target",
         f"_Fingerprint: DB ~ **{db}**, features: "
         f"{', '.join(k for k, v in feats.items() if v) or 'none detected'}._", ""]

    sqli = [f for f in reportable if f.get("template") == "sqli-error-based"]
    xss = [f for f in reportable if f.get("template") == "xss-reflected"]

    # ── Confirmed SQLi -> subtype payloads (DB-tailored) + sqlmap ──
    if sqli:
        pay = SQLI_PAYLOADS.get(db, SQLI_PAYLOADS["generic"])
        for f in sqli:
            u = f.get("url", ""); p = _param_of(u)
            base = u.split("%27")[0].split("'")[0]   # clean baseline URL (drop the probe quote)
            L += [f"### SQL injection — param `{p}`  [CONFIRMED - DB {db}]",
                  "- [confirmed] **Error-based: working** (a single quote already broke the response).",
                  "- Try next (paste into the param — correct payloads for this DB):",
                  f"  - Boolean-blind:  `{p}={pay['boolean'][0]}` (normal) vs `{p}={pay['boolean'][1]}` (differs)",
                  f"  - Time-based:     `{p}={pay['time']}`  -> ~5s delay = blind SQLi",
                  f"  - Version (UNION):`{p}={pay['version']}`",
                  f"  - Auto-extract everything:  `sqlmap -u \"{base}\" --batch --dbs --dump`",
                  f"  - Reference: {TEST_REFS['sqli']}", ""]

    # ── Confirmed reflected XSS -> stored/DOM to-try ──
    if xss:
        for f in xss:
            u = f.get("url", ""); p = _param_of(u)
            L += [f"### Cross-site scripting — param `{p}`  [reflected CONFIRMED]",
                  "- [confirmed] **Reflected XSS**: input echoed unencoded. Try a script payload manually:",
                  f"  - `{p}=<script>alert(document.domain)</script>`  (or an `<svg onload>` variant)",
                  f"  - Reference: {TEST_REFS['xss']}", ""]

    # ── Relevant-but-manual classes (driven by detected features) ──
    manual = []
    if feats["params"]:
        manual.append(("Access control / IDOR",
                       "Numeric/object id params present. Log in as user A, request user B's id "
                       "(e.g. id+1) — another user's record returned = IDOR.", TEST_REFS["access"]))
    if feats["login"]:
        manual.append(("Authentication",
                       "Login/admin surface present. Test: SQLi in the username (`' OR 1=1--`), "
                       "weak-password / credential spray, username enumeration, broken lockout, "
                       "password-reset flaws.", TEST_REFS["auth"]))
    if feats["stored_input"]:
        manual.append(("Stored XSS",
                       "User-content page (comment/post/feedback) found. Submit an XSS payload, "
                       "reload the page where it's shown — does it execute for other users?", TEST_REFS["xss"]))
    if feats["upload"]:
        manual.append(("Unrestricted file upload",
                       "Upload endpoint present. Try uploading a web shell / wrong content-type / "
                       "double extension; check if it's served back and executes.", TEST_REFS["upload"]))
    if feats["api"]:
        manual.append(("API auth / BOLA / mass-assignment",
                       "API surface present. Test object-level auth (swap ids), missing function-level "
                       "auth, and mass-assignment (extra JSON fields like role/isAdmin).", TEST_REFS["api"]))
    if feats["redirect"]:
        manual.append(("Open redirect / SSRF",
                       "A url/redirect/next param is present. Point it at an external host (open redirect) "
                       "or an internal one / cloud metadata (SSRF) and watch the response.", TEST_REFS["ssrf"]))
    if feats["login"] or feats["params"]:
        manual.append(("CSRF",
                       "State-changing actions present. Check whether they require an unpredictable "
                       "anti-CSRF token; if not, craft a cross-site request.", TEST_REFS["csrf"]))

    if manual:
        L += ["### Check manually (relevant to this site — Ultron can't auto-confirm)"]
        for name, how, ref in manual:
            L += [f"- **{name}** — {how}", f"  - Reference: {ref}"]
        L.append("")

    # ── Playbook recall: surface YOUR accumulated techniques for this stack ──
    try:
        from core import playbook as pb
        feat_q = " ".join(k for k, v in feats.items() if v)
        stack_q = (("" if db == "generic" else db) + " " + feat_q).strip()
        hits = pb.recall(query=stack_q or "injection", stack=stack_q, top_k=6)
        if hits:
            L += ["### From your playbook (recalled for this stack)"]
            for e in hits:
                tag = "PROVEN" if e.get("validated") else "ref"
                line = f"- [{tag}] {e.get('class')}: {e.get('technique')}"
                if e.get("payload"):
                    line += f"  ->  `{e['payload'][:70]}`"
                L.append(line)
                if e.get("ref"):
                    L.append(f"  - {e['ref']}")
            L.append("")
    except Exception:
        pass

    if not sqli and not xss and not manual:
        L.append("_No auto-findings and no high-signal features detected — review the crawled "
                 "endpoints manually._")
    return L


def format_bb_report(target, findings, exploits_map, pipeline_data, validated):
    """Build a platform-ready PoC report.md — only gate-passed findings get
    a full write-up; filtered ones are listed transparently. Each finding
    carries a `_gate` dict from _validate_finding()."""
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    # defensive: a malformed finding (a missing template/severity/url key from any probe)
    # must not KeyError-crash the whole report. Normalize before rendering.
    for f in findings or []:
        f.setdefault("template", "unknown")
        f.setdefault("severity", "info")
        f.setdefault("url", "")
        f.setdefault("_gate", {"report": False, "tier": "P5", "score": 0, "confidence": "weak"})

    reportable = [f for f in findings if f.get("_gate", {}).get("report")]
    dropped = [f for f in findings if not f.get("_gate", {}).get("report")]
    # Cluster duplicate findings (same class on many endpoints -> one grouped entry).
    reportable = dedup_findings(reportable)
    # Triage order — highest expected-value bug first (priority desc, severity as tiebreak),
    # so the hunter works the best finding first, not just the alphabetically-first critical.
    reportable.sort(key=lambda f: (-f.get("_gate", {}).get("priority", 0),
                                   _order.get(f.get("severity"), 9)))

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
        "**Workflow:** Recon -> Hunt -> Validate -> Quality Gate -> Report (JARVIS Ultron)",
        "",
        "## Executive Summary",
        f"- Reportable findings: **{len(reportable)}** ({tier_line})",
        f"- Filtered by validation gate: {len(dropped)} (noise / unconfirmed / informational)",
        f"- Re-probe validation run: {'yes' if validated else 'no'}",
    ]
    if reportable:
        _top = reportable[0]
        lines.append(f"- Top priority: **{_top['template']}** "
                     f"({_top['_gate'].get('priority', 0)}/100 triage, {_top['_gate']['tier']})")
    lines += [
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
            if f.get("_also_affected"):
                _more = f["_also_affected"]
                lines.append(f"- **Also affected ({len(_more)}):** " + ", ".join(_more[:10])
                             + (f" ...(+{len(_more) - 10} more)" if len(_more) > 10 else ""))
            lines.append(f"- **Status:** {'Confirmed live' if f.get('validated') else 'Reported by scanner (unconfirmed)'}")
            lines.append(f"- **Confidence:** {g.get('confidence', 'candidate').upper()} "
                         f"({g['score']}/7 quality checks)")
            lines.append(f"- **Priority:** {g.get('priority', 0)}/100 (triage: severity x confidence, +exploit)")
            if g.get("exploitability"):
                lines.append(f"- **Exploitability:** {g['exploitability']}")
            # F3 — CWE + preliminary CVSS per finding (from the canonical Evidence Object).
            try:
                from core import evidence as _ev
                _obj = _ev.build(f, target)
                lines.append(f"- **Weakness:** {_obj['cwe']['id']} — {_obj['cwe']['name']}")
                _cv = _obj['cvss']
                _pv = _cv.get('provisional')
                lines.append(f"- **CVSS 3.1 (preliminary):** {'up to ' if _pv else ''}{_cv['score']} "
                             f"({_cv['severity']})"
                             f"{' — candidate (unconfirmed, provisional)' if _pv else ''} `{_cv['vector']}`")
            except Exception:
                pass
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
            lines.append(f"- **Impact:** {impact_line(f)}")
            lines.append("- **Remediation:** "
                         + ("Patch to a fixed version per the CVE advisory." if f.get("cve")
                            else "Apply the vendor fix / config hardening for this vulnerability class."))

    if dropped:
        lines += ["", "## Filtered by Validation Gate",
                  "_Surfaced by the scanner but withheld — would be closed as N/A / informational._"]
        for f in dropped[:25]:
            why = f.get("_gate", {}).get("drop", "low confidence")
            lines.append(f"- `{f['template']}` ({f['severity']}) — {why}")

    # Tailored test plan — what to check on THIS target + how (auto vs manual)
    lines += build_test_plan(target, findings, pipeline_data)

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
