"""
Ultron — CVE lookup / NVD cluster (Phase B extraction, move-only).

CVE product-keyword matching + exploit lookup (NVD / GitHub / Exploit-DB) + NVD keyword
search, lifted verbatim out of the ultron_agent god-class. Free functions with no `self`.
find_exploits takes an optional save_report callback so it stays decoupled from the
agent's stateful report writer (the agent passes self.save_report in).

External deps: stdlib (urllib/json/re/datetime) + core.throttle. Network I/O only.
"""
import datetime

from core.throttle import throttle


def cve_product_keywords(entry: dict) -> set:
    """Extract product-name keywords from a CVE watchlist entry's affected CPE list + description."""
    kws = set()
    for a in entry.get("affected", []):
        # "vendor:product version" -> take product, drop version
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


def match_products(cve_kws: set, svc_toks: set) -> list:
    """Bidirectional substring match (min len 3) between CVE products and host services."""
    hits = set()
    for ct in cve_kws:
        for st in svc_toks:
            if len(ct) >= 3 and len(st) >= 3 and (ct in st or st in ct):
                hits.add(st)
    return sorted(hits)


def find_exploits(cve_id: str, save_report=None) -> dict:
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
            lines.append(f"  *{p['stars']}  {p['name']}")
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
    if save_report:
        save_report(f"exploits_{cve_id.replace('-', '_')}", report)

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


def search_cve(keyword: str, severity: str = "", days_back: int = 7) -> dict:
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

    # Date filter — NVD v2 REQUIRES pubStartDate and pubEndDate as a PAIR;
    # sending only the start date returns HTTP 404. (Range also capped at 120 days.)
    if days_back and days_back > 0:
        end = _dt.datetime.utcnow()
        start = end - _dt.timedelta(days=min(days_back, 120))
        params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT23:59:59.999")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    print(f"[ULTRON] NVD search: {url}")

    try:
        hdrs = {"User-Agent": "JARVIS-Ultron/1.0"}
        if _nvd_key:
            hdrs["apiKey"] = _nvd_key
        req = urllib.request.Request(url, headers=hdrs)
        data, last_err = None, None
        for attempt in range(2):              # NVD (esp. keyless) is slow/flaky — one retry
            try:
                throttle("nvd")   # 50/30s (key) or 5/30s (no key) — space to avoid 429
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = _json.loads(resp.read().decode())
                break
            except Exception as e:
                last_err = e
                if attempt == 0:
                    import time as _t
                    _t.sleep(2)
        if data is None:
            hint = "" if _nvd_key else " — set NVD_API_KEY in .env for a faster, more reliable quota"
            return {"success": False, "message": f"NVD slow/unreachable: {str(last_err)[:50]}{hint}", "data": {}}
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
