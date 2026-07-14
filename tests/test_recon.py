"""
friday-recon test suite (pytest) — offline, no Ollama/network needed.
Covers the security-critical surface: SSRF guard, HackingTool allowlist + injection
refusal, the bug-bounty validation gate, KB retrieval, Burp parsing, target memory,
and the Batch-1/2 hardening (no shell sinks, no bash -lc).
"""
import os
import sys
import base64
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── SSRF guard ────────────────────────────────────────────────────────────────
import core.url_guard as ug

def test_ssrf_blocks_private():
    for u in ("http://127.0.0.1/", "http://169.254.169.254/", "http://192.168.1.1/", "http://10.0.0.5/"):
        ok, _ = ug.is_safe_url(u)
        assert not ok, u

def test_ssrf_blocks_encoded_ips():
    for u in ("http://2130706433/", "http://0x7f000001/", "http://017700000001/"):
        ok, _ = ug.is_safe_url(u)
        assert not ok, u

def test_ssrf_allows_public():
    ok, _ = ug.is_safe_url("https://example.com")
    assert ok

def test_ssrf_blocks_non_http():
    assert not ug.is_safe_url("file:///etc/passwd")[0]
    assert not ug.is_safe_url("ftp://example.com")[0]

def test_safe_get_blocks_redirect_to_internal(monkeypatch):
    import types
    class _R:
        def __init__(s, code, loc=None):
            s.status_code = code; s.headers = {"location": loc} if loc else {}; s.content = b""
    fake = types.SimpleNamespace(get=lambda url, **kw: _R(302, "http://169.254.169.254/"))
    monkeypatch.setitem(sys.modules, "requests", fake)
    import pytest
    with pytest.raises(ValueError):
        ug.safe_get("https://example.com/redir")


# ── HackingTool allowlist + injection refusal ──────────────────────────────────
from agents.ultron.hackingtool import ht_wrapper as htw

def test_ht_blocks_offensive():
    assert htw.ht_run("post_exploitation.Havoc")["status"] == "refused"

def test_ht_gates_extended():
    assert htw.ht_run("web_attack.Ffuf", "x")["status"] == "refused"

def test_ht_refuses_arg_injection():
    assert htw.ht_run("information_gathering.Amass", "a.com; rm -rf /")["status"] == "refused"


# ── validation gate ─────────────────────────────────────────────────────────────
from agents.ultron.ultron_agent import ultron_agent as U

def test_apex_domain_for_subfinder():
    """Subfinder must enumerate the registrable APEX — 'www.x.com' was giving 0 subs because
    subfinder looked for '*.www.x.com'. (bhavansdubai.com dogfood: 0 -> 5 subs.)"""
    a = _ult._apex_domain
    assert a("www.bhavansdubai.com") == "bhavansdubai.com"
    assert a("https://www.bhavansdubai.com/x") == "bhavansdubai.com"
    assert a("lms.bhavansdubai.com") == "bhavansdubai.com"
    assert a("bhavansdubai.com") == "bhavansdubai.com"          # apex unchanged
    assert a("shop.example.co.uk") == "example.co.uk"           # two-part TLD kept
    assert a("a.b.example.com") == "example.com"
    assert a("10.0.0.1") == "10.0.0.1" and a("localhost") == "localhost"  # IP/host unchanged


def test_sitemap_paths_discovery(monkeypatch):
    """Passive sitemap discovery follows a nested sitemap INDEX to child sitemaps and returns
    the real page URLs (browser UA — WP serves empty to python-requests)."""
    class _R:
        def __init__(s, t): s.text = t; s.status_code = 200; s.headers = {}
    INDEX = "<sitemapindex><sitemap><loc>https://t.com/page-sitemap.xml</loc></sitemap></sitemapindex>"
    CHILD = "<urlset><url><loc>https://t.com/admission/</loc></url><url><loc>https://t.com/refer/</loc></url></urlset>"
    def g(url, timeout=8, headers=None, allow_redirects=True):
        if url.endswith("/robots.txt"): return _R("Sitemap: https://t.com/sitemap.xml")
        if "page-sitemap" in url: return _R(CHILD)
        if "sitemap" in url: return _R(INDEX)
        return _R("")
    monkeypatch.setattr(_ult, "_http_get", g)
    paths = _ult._sitemap_paths("https://t.com")
    assert "https://t.com/admission/" in paths and "https://t.com/refer/" in paths
    assert not any(".xml" in p for p in paths)


def test_gate_keeps_real_finding():
    f = {"template": "CVE-2021-44228", "severity": "critical",
         "url": "https://t.com/api", "cve": "CVE-2021-44228", "validated": True}
    g = U._validate_finding(f, {"CVE-2021-44228": "poc"})
    assert g["report"] and g["score"] == 7 and g["tier"].startswith("P1")

def test_gate_drops_noise():
    for tmpl in ("tls-version", "missing-security-header", "tech-detect-nginx"):
        g = U._validate_finding({"template": tmpl, "severity": "low", "url": "https://t.com",
                                 "cve": "", "validated": False}, {})
        assert not g["report"], tmpl

def test_gate_triage_priority():
    """Deterministic triage priority: confirmed high outranks unproven critical (+ exploit bonus)."""
    from agents.ultron import gate
    assert gate.triage("critical", "reproduced", True) > gate.triage("high", "reproduced") \
        > gate.triage("critical", "candidate") > gate.triage("low", "weak") >= 0
    assert gate.triage("critical", "reproduced", True) <= 100
    g = U._validate_finding({"template": "sqli", "severity": "high",
                             "url": "http://t/p?id=1", "validated": True, "cve": ""}, {})
    # reproduced app-vuln is demonstrably exploitable (no CVE needed) -> exploit bonus
    assert g["priority"] == gate.triage("high", "reproduced", True)
    assert g["exploitability"] == "reproduced on target"

def test_report_triage_ordering():
    """Report ranks findings by triage priority (best bug first), exec summary names top."""
    findings = [
        {"template": "cve-critical-unproven", "severity": "critical", "url": "http://t/a",
         "cve": "", "validated": False},
        {"template": "sqli-error-based", "severity": "high", "url": "http://t/p?id=1",
         "cve": "", "validated": True, "evidence": "db err"},
    ]
    for f in findings:
        f["_gate"] = U._validate_finding(f, {})
    rpt = U._format_bb_report("t.com", findings, {}, {"urls": []}, True)
    assert rpt.index("sqli-error-based") < rpt.index("cve-critical-unproven")
    assert "Top priority: **sqli-error-based**" in rpt and "Priority:" in rpt
    rpt.encode("cp1252")

def test_impact_data_driven():
    """Impact line is evidence-aware: canonical class impact + concrete param/endpoint + confidence."""
    from agents.ultron import report
    from core import evidence
    assert "database" in evidence.class_impact("sqli-error-based").lower()
    line = report.impact_line({"template": "sqli-error-based", "severity": "high",
                               "url": "http://t/p?id=1", "cve": "",
                               "_gate": {"confidence": "reproduced"}})
    assert "`id`" in line and "parameter" in line and "Reproduced" in line
    line2 = report.impact_line({"template": "idor-bola", "severity": "medium",
                                "url": "http://t/api/user/5", "cve": "",
                                "_gate": {"confidence": "candidate"}})
    assert "`/api/user/5`" in line2 and "Candidate" in line2
    line.encode("cp1252"); line2.encode("cp1252")


def test_evidence_cvss_provisional():
    """Confidence-gated CVSS: a REPRODUCED sqli shows the full 9.8; a CANDIDATE must render
    'up to' + a candidate caveat, never a bare confirmed-looking 9.8 (triager overclaim FP)."""
    from core import evidence
    conf = evidence.build({"template": "sqli-error-based", "severity": "high", "url": "http://t/s?q=1",
                           "validated": True, "_gate": {"confidence": "reproduced"}}, "t")
    assert not conf["cvss"]["provisional"] and "up to" not in evidence.to_markdown(conf)
    cand = evidence.build({"template": "sqli-error-based", "severity": "high", "url": "http://t/s?q=1",
                           "_gate": {"confidence": "candidate"}}, "t")
    md = evidence.to_markdown(cand)
    assert cand["cvss"]["provisional"] and "up to" in md and "candidate" in md.lower()


def test_evidence_preconditions():
    """Attacker preconditions derived deterministically from the CVSS vector: sqli (PR:N/UI:N/AV:N)
    = unauthenticated·network·no-UI; xss (UI:R) = requires victim interaction."""
    from core import evidence
    o = evidence.build({"template": "sqli-error-based", "severity": "high", "url": "http://t/s?q=1"}, "t")
    s = o["preconditions"]["summary"].lower()
    assert "unauthenticated" in s and "network" in s and "no user interaction" in s
    assert "Preconditions:" in evidence.to_markdown(o)
    x = evidence.build({"template": "xss-reflected", "severity": "medium", "url": "http://t/x?q=1"}, "t")
    assert "victim interaction" in x["preconditions"]["summary"].lower()


# ── Auth Matrix (v1.3 keystone) ──────────────────────────────────────────────────
def test_auth_expected_access():
    ea = _ult._expected_access
    assert ea("/admin/users")[0] == "admin" and ea("/admin/x")[1] == "high"
    assert ea("/orders/42")[0] == "owner"
    assert ea("/login")[0] == "guest"
    assert ea("/profile")[0] == "self"
    assert ea("/foo")[0] == "user"

def test_auth_matrix_bfla(monkeypatch):
    # anon reaching an admin-expected path = BFLA (broken function-level authz), HIGH confidence.
    from core import session_manager as sm
    sm.clear()
    _patch_http(monkeypatch, lambda url, timeout=8, headers=None, allow_redirects=True: _FakeResp("panel", 200))
    res = _ult.ultron_agent.auth_matrix(["http://t/admin/users", "http://t/products"])
    bfla = [x for x in res["data"]["findings"] if x["template"] == "bfla-broken-function-auth"]
    assert bfla and "/admin/users" in bfla[0]["url"] and "HIGH" in bfla[0]["evidence"]
    assert not any("/products" in x["url"] for x in bfla)
    assert "Expected" in res["data"]["table_md"]

def test_auth_matrix_bola(monkeypatch):
    # id-bearing path with 2 principals -> delegates to idor_check (no new BOLA logic).
    from core import session_manager as sm
    sm.clear(); sm.set_session("userA", cookie="u=1", role="user"); sm.set_session("userB", cookie="u=2", role="user")
    def _get(url, timeout=8, headers=None, allow_redirects=True):
        if not (headers or {}).get("Cookie"):
            return _FakeResp("forbidden", 403)
        return _FakeResp("owner's order record " * 6, 200)
    _patch_http(monkeypatch, _get)
    res = _ult.ultron_agent.auth_matrix(["http://t/orders/1"], owner="userA", attacker="userB")
    sm.clear()
    assert "idor-bola" in [x["template"] for x in res["data"]["findings"]]

def test_auth_matrix_r6(monkeypatch):
    # R6: anon 2xx on owner/self path = missing-authentication; default 'user' path must NOT trigger.
    from core import session_manager as sm
    sm.clear()
    _patch_http(monkeypatch, lambda url, timeout=8, headers=None, allow_redirects=True: _FakeResp("record", 200))
    r = _ult.ultron_agent.auth_matrix(["http://t/orders/1"])            # owner (id) -> flag
    assert "missing-authentication" in [f["template"] for f in r["data"]["findings"]]
    r2 = _ult.ultron_agent.auth_matrix(["http://t/products"])           # default 'user' -> no flag
    assert not any(f["template"] == "missing-authentication" for f in r2["data"]["findings"])

def test_oast_ssrf(monkeypatch):
    import urllib.request, urllib.parse
    def g_vuln(url, timeout=8, headers=None, allow_redirects=True):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        if q.get("url"):
            try: urllib.request.urlopen(q["url"], timeout=2).read()   # server-side fetch = blind SSRF -> listener hit
            except Exception: pass
        return _FakeResp("")
    _patch_http(monkeypatch, g_vuln)
    r = _ult.ultron_agent.oast_ssrf("http://target/fetch?url=x", param="url", wait=3.0)
    f = r["data"]["findings"]
    assert f and f[0]["template"] == "ssrf-oob-confirmed" and "CONFIRMED" in f[0]["evidence"] and f[0].get("oob")
    _patch_http(monkeypatch, lambda url, timeout=8, headers=None, allow_redirects=True: _FakeResp(""))
    assert not _ult.ultron_agent.oast_ssrf("http://safe/x?url=y", param="url", wait=1.0)["data"]["findings"]


def test_secrets(monkeypatch):
    from core import secrets as S
    names = [n for n, _ in S.find_secrets('k="AKIAIOSFODNN7EXAMPLE"; t="ghp_' + "a" * 36 + '"')]
    assert "AWS access key id" in names and any("GitHub" in n for n in names)
    assert not S.find_secrets("normal text with api key secret words")
    assert any(e.startswith("/api/users") for e in S.find_endpoints('fetch("/api/users?id=1")'))
    assert S.file_signature(".env", "DB_PASSWORD=x") and not S.file_signature(".git/config", "<html>spa</html>")
    def g(url, timeout=8, headers=None, allow_redirects=True):
        if url.endswith("app.js"): return _FakeResp('const K="AKIAIOSFODNN7EXAMPLE";')
        if url.endswith(".env"):   return _FakeResp("APP_SECRET=abc\nDB_PASSWORD=x", 200)
        return _FakeResp("<html></html>", 404)
    _patch_http(monkeypatch, g)
    tmpls = {f["template"] for f in
             _ult.ultron_agent.secret_scan("https://t.com", urls=["https://t.com/app.js"])["data"]["findings"]}
    assert "exposed-secret" in tmpls and "sensitive-file" in tmpls


def test_cors_misconfig(monkeypatch):
    class _CR:
        def __init__(s, h): s.text = ""; s.status_code = 200; s.headers = h
    _patch_http(monkeypatch, lambda url, timeout=8, headers=None, allow_redirects=True: _CR(
        {"Access-Control-Allow-Origin": (headers or {}).get("Origin", ""), "Access-Control-Allow-Credentials": "true"}))
    f = _ult.ultron_agent.cors_check(["https://t.com/api"])["data"]["findings"]
    assert f and f[0]["severity"] == "high"                                     # reflected + creds
    _patch_http(monkeypatch, lambda url, timeout=8, headers=None, allow_redirects=True: _CR({"Access-Control-Allow-Origin": (headers or {}).get("Origin", "")}))
    assert _ult.ultron_agent.cors_check(["https://t.com/x"])["data"]["findings"][0]["severity"] == "medium"  # reflected, no creds
    _patch_http(monkeypatch, lambda url, timeout=8, headers=None, allow_redirects=True: _CR({"Access-Control-Allow-Origin": "https://t.com"}))
    assert not _ult.ultron_agent.cors_check(["https://t.com/y"])["data"]["findings"]   # same-origin -> clean


def test_subdomain_takeover():
    from core import takeover as TK
    r = TK.scan(["gh.t.com"], fetch=lambda u, timeout=8: (404, "There isn't a GitHub Pages site here."))
    assert any(f["template"] == "subdomain-takeover" for f in r["data"]["findings"])
    assert "GitHub Pages" in r["data"]["findings"][0]["evidence"]
    assert TK.scan(["s3.t.com"], fetch=lambda u, timeout=8: (404, "<Code>NoSuchBucket</Code>"))["data"]["findings"]
    assert not TK.scan(["ok.t.com"], fetch=lambda u, timeout=8: (200, "welcome 404 not found"))["data"]["findings"]


def test_jwt_analyzer():
    import base64, json
    from core import jwt_analyzer as J
    def mk(hdr, pl):
        b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
        return f"{b(hdr)}.{b(pl)}.sig"
    assert "jwt-alg-none" in {f["template"] for f in
        J.analyze(mk({"alg": "none"}, {"sub": "1", "exp": 9999999999}))["data"]["findings"]}
    t2 = {f["template"] for f in
        J.analyze(mk({"alg": "HS256", "jku": "https://evil/jwks", "kid": "1"}, {"sub": "1", "role": "user"}))["data"]["findings"]}
    for want in ("jwt-weak-alg", "jwt-jku-ssrf", "jwt-kid-injection", "jwt-missing-exp", "jwt-sensitive-claims"):
        assert want in t2, want
    assert not J.analyze(mk({"alg": "RS256"}, {"sub": "1", "iat": 1000, "exp": 4600}))["data"]["findings"]
    assert not J.analyze("plainstring")["success"]


def test_idor_content_aware(monkeypatch):
    # R5: content-aware ownership. Real BOLA (attacker gets owner's EXACT body, crAPI vehicle shape) flags;
    # self-scoped endpoint (each principal gets own same-length body, VAmPI /me) must NOT flag.
    from core import session_manager as sm
    sm.clear(); sm.set_session("userA", cookie="uid=1", role="user"); sm.set_session("userB", cookie="uid=2", role="user")
    OWNER = "alice private record padded to a stable length 0123456789"
    def g_bola(url, timeout=8, headers=None, allow_redirects=True):
        if not (headers or {}).get("Cookie"): return _FakeResp("login", 401)
        return _FakeResp(OWNER)                                     # anyone with a cookie reads owner's exact data
    _patch_http(monkeypatch, g_bola)
    assert "idor-bola" in [f["template"] for f in
        _ult.ultron_agent.idor_check("http://t/vehicle/xyz/location", "userA", "userB")["data"]["findings"]]
    def g_self(url, timeout=8, headers=None, allow_redirects=True):
        ck = (headers or {}).get("Cookie", "")
        if not ck: return _FakeResp("login here pad 0", 401)
        who = "AAAA" if "uid=1" in ck else "BBBB"                  # each caller sees its own same-length record
        return _FakeResp(f"self dashboard for {who} padded identical len 01234567")
    _patch_http(monkeypatch, g_self)
    r2 = _ult.ultron_agent.idor_check("http://t/me", "userA", "userB")
    sm.clear()
    assert not r2["data"]["findings"]                              # self-scoped FP killed

def test_report_dedup_clustering():
    """Same class on N endpoints of one host collapses to ONE grouped finding (parity)."""
    from agents.ultron import report
    mk = lambda i, host="t": {"template": "sqli-error-based", "severity": "high",
        "url": f"http://{host}/p?id={i}", "cve": "", "evidence": "db err",
        "_gate": {"report": True, "tier": "P2", "priority": 70, "score": 6, "confidence": "reproduced"}}
    d = report.dedup_findings([mk(0), mk(1), mk(2)])
    assert len(d) == 1 and len(d[0]["_also_affected"]) == 2
    assert len(report.dedup_findings([mk(0), mk(0, host="other")])) == 2
    orig = mk(0)
    report.dedup_findings([orig, mk(1)])
    assert "_also_affected" not in orig
    rpt = report.format_bb_report("t.com", [dict(mk(i)) for i in range(3)], {}, {"urls": []}, True)
    assert "Also affected (2)" in rpt and "Reportable findings: **1**" in rpt
    rpt.encode("cp1252")

def test_v12_engine_end_to_end(tmp_path):
    """v1.2 integration: one real bug_bounty() run fires the whole chain — F4 timeline+package,
    gate filter, triage ranking, data-driven impact, dedup, exploitability, evidence (parity)."""
    import os, re, zipfile
    from core import timeline, package
    timeline._RUNS_DIR = os.path.join(str(tmp_path), "runs")
    urls = [f"http://shop.example.com/item?id={i}" for i in range(3)] + ["http://shop.example.com/s?q=1"]
    sqli = [{"template": "sqli-error-based", "severity": "high", "url": u, "cve": "",
             "validated": True, "evidence": "error in your SQL syntax", "repro": ["'"]} for u in urls[:3]]
    cve = [{"template": "CVE-2021-44228", "severity": "critical", "url": "http://shop.example.com/api",
            "cve": "CVE-2021-44228", "validated": True}]
    noise = [{"template": "tls-version", "severity": "low", "url": "http://shop.example.com", "cve": ""}]

    def _save(name, body):
        p = os.path.join(str(tmp_path), "reports", name + ".md")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write(body)
        return p

    stubs = {"full_pipeline": lambda *a, **k: {"success": True, "data":
                {"urls": urls, "post_endpoints": [], "sections": {"nuclei": "", "httpx": ""}}},
             "_probe_injection": lambda *a, **k: [dict(x) for x in sqli + cve + noise],
             "_probe_post": lambda *a, **k: [], "_probe_path_params": lambda *a, **k: [],
             "_probe_stored_xss": lambda *a, **k: [],
             "collect_evidence": lambda *a, **k: {"success": True, "data": {}},
             "find_exploits": lambda *a, **k: {"success": True, "data": {"pocs": [{"url": "p"}], "total": 1}, "message": "p"},
             "save_report": _save}
    orig = {n: getattr(U, n) for n in stubs}
    for n, fn in stubs.items():
        setattr(U, n, fn)
    try:
        r = U.bug_bounty("shop.example.com", force=True)
        rid = r["data"].get("run_id")
        rpt = r["data"].get("report", "")
        tl = timeline.load(rid)
        assert tl and all(s in [e["step"] for e in tl["events"]] for s in ("recon", "probe", "idor", "gate", "evidence"))
        assert "Priority:" in rpt and "Top priority:" in rpt
        assert "Also affected (2)" in rpt          # dedup
        assert "`id`" in rpt                        # data-driven impact
        assert "reproduced on target" in rpt        # exploitability
        assert "Filtered by Validation Gate" in rpt and "tls-version" in rpt  # gate
        prios = [int(x) for x in re.findall(r"\*\*Priority:\*\* (\d+)/100", rpt)]
        assert prios and prios == sorted(prios, reverse=True)
        pk = package.build_package(rid)
        assert pk["success"]
        with zipfile.ZipFile(pk["data"]["path"]) as z:
            names = z.namelist()
        assert "timeline.json" in names and any(n.endswith(".md") for n in names)
    finally:
        for n, fn in orig.items():
            setattr(U, n, fn)


# ── KB retrieval (offline) ──────────────────────────────────────────────────────
from core import security_kb as kb

def test_kb_search_finds_methodology():
    hits = kb.search("subdomain takeover")
    assert hits and hits[0]["score"] > 0.1

def test_kb_wordlist_resolves():
    r = kb.wordlist_path("ssrf")
    assert r["success"] and "ssrf" in r["message"].lower()


# ── Burp ingest + tagging ───────────────────────────────────────────────────────
from core import burp_ingest

def test_burp_parse_and_tag():
    def itm(url, m, st, req, resp):
        return (f'<item><url>{url}</url><method>{m}</method><status>{st}</status>'
                f'<request base64="true">{base64.b64encode(req.encode()).decode()}</request>'
                f'<response base64="true">{base64.b64encode(resp.encode()).decode()}</response></item>')
    xml = ('<?xml version="1.0"?><items>'
           + itm("https://t.com/api/v1/x", "GET", "200",
                 "GET /api/v1/x HTTP/1.1\r\nAuthorization: Bearer eyJa.eyJb.sig\r\n\r\n",
                 "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
           + itm("https://t.com/graphql", "POST", "200",
                 'POST /graphql HTTP/1.1\r\n\r\n{"query":"{me}"}', "HTTP/1.1 200\r\n\r\n")
           + '</items>')
    p = os.path.join(tempfile.gettempdir(), "burp_pytest.xml")
    open(p, "w", encoding="utf-8").write(xml)
    try:
        d = burp_ingest.parse_export(p)["data"]
        assert d["items"] == 2 and len(d["endpoints"]) == 2
        assert d["tags"].get("jwt") and d["tags"].get("graphql") and d["tags"].get("apis")
    finally:
        os.remove(p)


# ── target profiles ─────────────────────────────────────────────────────────────
def test_target_profile_roundtrip():
    import core.target_profiles as tp
    saved = tp._FILE
    tp._FILE = os.path.join(tempfile.gettempdir(), "tp_pytest.json")
    try:
        if os.path.exists(tp._FILE): os.remove(tp._FILE)
        tp.record_scan("acme.com", "nmap", "3 ports")
        tp.record_tags("acme.com", {"jwt": ["https://acme.com/api"]})
        s = tp.summary("acme.com")
        assert "acme.com" in s["message"] and "JWT" in s["message"]
    finally:
        if os.path.exists(tp._FILE): os.remove(tp._FILE)
        tp._FILE = saved


# ── github hunt regex (offline) ─────────────────────────────────────────────────
from core import github_hunt as ghh

def test_github_secret_regex():
    pat = ghh._SECRET_FILES
    assert pat.search(".env") and pat.search("config/credentials.json") and pat.search("k/id_rsa")
    assert not pat.search("README.md") and not pat.search("src/app.py")


# ── Batch-1/2 hardening guards (no shell sinks) ─────────────────────────────────
def _code(path):
    return "\n".join(l.split("#", 1)[0] for l in open(path, encoding="utf-8"))

def test_no_shell_sinks_in_ultron():
    c = _code("agents/ultron/ultron_agent.py")
    assert "shell=True" not in c and "os.system(" not in c

def test_ht_run_no_bash_lc():
    c = _code("agents/ultron/hackingtool/scripts/ht_run.py")
    assert '"-lc"' not in c and "'-lc'" not in c


# ── injection smell-test (_probe_injection) — patches the _http_get seam ─────────
import agents.ultron.ultron_agent as _ult


class _FakeResp:
    def __init__(self, text, code=200):
        self.text = text; self.status_code = code


def _patch_http(monkeypatch, getter):
    monkeypatch.setattr(_ult, "_http_get", getter)


def test_rate_gate_safety():
    """Safety promise: _rate_gate throttles public hosts (RoE rps / 3-rps default) but leaves
    localhost unthrottled — guards against a refactor hammering a real bounty target. No network."""
    import time, os
    roe = os.path.join("data", "roe.json"); bak = roe + ".ratetest.bak"
    had = os.path.exists(roe)
    if had:
        os.replace(roe, bak)
    try:
        _ult._RATE_LAST[0] = 0.0
        t0 = time.time()
        for _ in range(8):
            _ult._rate_gate("http://127.0.0.1:8000/x")
        assert time.time() - t0 < 0.25, "localhost must be unthrottled"
        _ult._RATE_LAST[0] = 0.0
        t0 = time.time()
        for _ in range(3):
            _ult._rate_gate("http://example.com/x")
        assert time.time() - t0 >= 0.55, "public host must be throttled to ~3 rps"
    finally:
        if had:
            os.replace(bak, roe)


def test_write_bola_oracle(monkeypatch):
    """Opt-in write-BOLA oracle: attacker mutates owner's object -> CRITICAL + auto-revert;
    destructive fields refused; enforced-ownership = no finding. (VAmPI dogfood.)"""
    import json as _json
    from core import session_manager as sm
    U = _ult.ultron_agent
    class _J:
        def __init__(s, obj, c=200): s._o = obj; s.status_code = c; s.text = _json.dumps(obj); s.headers = {}
        def json(s): return s._o
    sm.clear(); sm.set_session("userA", cookie="uid=1"); sm.set_session("userB", cookie="uid=2")
    # vulnerable: no ownership check on write
    state = {"email": "alice@orig.com"}
    monkeypatch.setattr(_ult, "_http_get", lambda url, timeout=8, headers=None, allow_redirects=True: _J(dict(state)))
    def w(method, url, json_body=None, timeout=8, headers=None):
        state.update(json_body or {}); return _J(dict(state), 204)
    monkeypatch.setattr(_ult, "_http_write", w)
    r = U.write_bola_check("http://t/users/v1/alice", field="email", owner="userA", attacker="userB")
    assert "idor-bola-write" in [f["template"] for f in r["data"]["findings"]]
    assert r["data"]["reverted"] is True and state["email"] == "alice@orig.com"
    # destructive field refused
    rp = U.write_bola_check("http://t/users/v1/alice", field="password", owner="userA", attacker="userB")
    assert not rp["success"] and "Refusing" in rp["message"]
    # enforced ownership -> no finding
    state2 = {"email": "bob@orig.com"}
    monkeypatch.setattr(_ult, "_http_get", lambda url, timeout=8, headers=None, allow_redirects=True: _J(dict(state2)))
    def w2(method, url, json_body=None, timeout=8, headers=None):
        ck = (headers or {}).get("Cookie", "")
        if ck == "uid=1": state2.update(json_body or {})
        return _J(dict(state2), 200 if ck == "uid=1" else 403)
    monkeypatch.setattr(_ult, "_http_write", w2)
    r2 = U.write_bola_check("http://t/users/v1/bob", field="email", owner="userA", attacker="userB")
    assert not r2["data"]["findings"]
    sm.clear()


def test_probe_flags_sqli_and_xss(monkeypatch):
    def _get(url, timeout=8, headers=None, allow_redirects=True):
        if "id=" in url and "%27" in url:
            return _FakeResp("Microsoft OLE DB Provider error: Unclosed quotation mark")
        if "jvz9xqk7z" in url:
            return _FakeResp("echo jvz9xqk7z<x> back to you")
        return _FakeResp("normal body " * 50)
    _patch_http(monkeypatch, _get)
    res = _ult.ultron_agent._probe_injection(
        ["http://t.com/n.aspx?id=1", "http://t.com/s.aspx?q=x", "http://t.com/flat.html"])
    tmpls = {r["template"] for r in res}
    assert "sqli-error-based" in tmpls and "xss-reflected" in tmpls
    assert not any("flat.html" in r["url"] for r in res)
    assert all(r["validated"] and r["evidence"] and r["repro"] for r in res)
    # raw request/response captured (not the fabricated `GET {url} HTTP/1.1` fallback)
    sq = [r for r in res if r["template"] == "sqli-error-based"][0]
    assert sq["request"].startswith("GET ") and "Host:" in sq["request"]
    assert "HTTP" in sq["response"]


def test_probe_sqli_anomaly(monkeypatch):
    # a quote -> 500 with NO DB-error string is an injection CANDIDATE of unconfirmed class,
    # not a CVSS-9.8 SQLi (DSVW dogfood: path/include/name/size all 500 on a quote non-SQL).
    def _get(url, timeout=8, headers=None, allow_redirects=True):
        if "%27" in url:
            return _FakeResp("", 500)              # quote -> empty 500, no error string
        return _FakeResp("healthy page " * 100, 200)
    _patch_http(monkeypatch, _get)
    res = _ult.ultron_agent._probe_injection(["http://t.com/n.aspx?id=1"])
    anom = [r for r in res if r["template"] == "injection-error-anomaly"]
    assert anom and anom[0]["severity"] == "medium" and "UNCONFIRMED" in anom[0]["evidence"]
    assert not [r for r in res if r["template"] == "sqli-error-based"]  # must NOT over-claim SQLi


def test_probe_type_error_dropped(monkeypatch):
    # FP-kill (DSVW `?size=` dogfood): a quote -> 500 via numeric-cast error (int("32'") ->
    # ValueError) is input-validation, NOT injection — must be DROPPED, not flagged as anomaly.
    def _get(url, timeout=8, headers=None, allow_redirects=True):
        if "%27" in url:
            return _FakeResp("Traceback...\nValueError: invalid literal for int() with base 10: \"32'\"", 500)
        return _FakeResp("healthy page " * 100, 200)
    _patch_http(monkeypatch, _get)
    res = _ult.ultron_agent._probe_injection(["http://t.com/n.aspx?size=32"])
    assert not [r for r in res if r["template"] == "injection-error-anomaly"]  # dropped
    assert not [r for r in res if r["template"] == "sqli-error-based"]


def test_probe_xss_context(monkeypatch):
    # reflection-context classifier: marker in a comment/rawtext element is inert (dropped);
    # marker in raw HTML element context is executable (flagged).
    mark = _ult._XSS_MARKER + "<x>"
    def _mk(body):
        def _get(url, timeout=8, headers=None, allow_redirects=True):
            if _ult._XSS_MARKER in url:
                return _FakeResp(body.replace("MARK", mark), 200)
            return _FakeResp("normal " * 50, 200)
        return _get
    _patch_http(monkeypatch, _mk("<html><!-- MARK --></html>"))
    assert not [r for r in _ult.ultron_agent._probe_injection(["http://t.com/p?q=1"])
                if r["template"] == "xss-reflected"]                     # comment -> dropped
    _patch_http(monkeypatch, _mk("<div>MARK</div>"))
    x = [r for r in _ult.ultron_agent._probe_injection(["http://t.com/p?q=1"])
         if r["template"] == "xss-reflected"]
    assert x and "executable" in x[0]["evidence"]                       # raw HTML -> flagged executable
    # multi-occurrence: attr AND raw-html reflection -> pick the STRONGEST (executable)
    _patch_http(monkeypatch, _mk('<input value="MARK"><div>MARK</div>'))
    xm = [r for r in _ult.ultron_agent._probe_injection(["http://t.com/p?q=1"])
          if r["template"] == "xss-reflected"]
    assert xm and "executable" in xm[0]["evidence"]


# ── Feature B: tailored test plan ───────────────────────────────────────────────
def test_plan_sqli_subtypes():
    findings = [{"template": "sqli-error-based", "severity": "high",
                 "url": "http://t.com/Comments.aspx?id=0%27", "validated": True,
                 "evidence": "OLE DB error", "_gate": {"report": True, "tier": "P2", "score": 6}}]
    pdata = {"sections": {"httpx": "[200] [Microsoft-IIS, ASP.NET]"},
             "urls": ["http://t.com/login.aspx", "http://t.com/Comments.aspx?id=0"]}
    txt = "\n".join(_ult.ultron_agent._build_test_plan("t.com", findings, pdata))
    for n in ("DB ~ **mssql**", "WAITFOR DELAY", "sqlmap -u", "Access control / IDOR", "Authentication"):
        assert n in txt, n
    assert "%27" not in txt.split("sqlmap")[1].split("\n")[0]

def test_plan_skips_irrelevant():
    txt = "\n".join(_ult.ultron_agent._build_test_plan("t.com", [], {"sections": {}, "urls": []}))
    assert "GraphQL" not in txt and "file upload" not in txt.lower()
    assert "No auto-findings" in txt


def test_scope_guard_flags_saas():
    # scope-independent: a SaaS host is flagged regardless of scope; a plain host with NO
    # program scope loaded is not. Back up/clear the user's data/scope.json so this is
    # deterministic (it used to fail when a live engagement scope was set).
    import os
    sc = os.path.join("data", "scope.json"); bak = sc + ".scopetest.bak"
    had = os.path.exists(sc)
    if had:
        os.replace(sc, bak)
    try:
        assert _ult._scope_check("foo.herokuapp.com")     # SaaS host -> flagged even with no scope
        assert not _ult._scope_check("example.com")        # plain host, no scope loaded -> no note
    finally:
        if had:
            os.replace(bak, sc)

def test_content_discovery_parsers(monkeypatch):
    import shutil
    # gobuster text parser (ffuf path uses JSON-file output, integration-verified)
    monkeypatch.setattr(shutil, "which", lambda t: "/x/gobuster" if t == "gobuster" else None)
    monkeypatch.setattr(_ult, "run_cmd", lambda *a, **k: "/admin (Status: 200)\n/x (Status: 301)\nnoise\n")
    assert _ult.ultron_agent.content_discovery("http://t.com")["data"]["count"] == 2
    # error sentinel must not be counted as a path
    monkeypatch.setattr(_ult, "run_cmd", lambda *a, **k: "Timed out.")
    assert not _ult.ultron_agent.content_discovery("http://t.com").get("data", {}).get("count")
    # no tool -> graceful
    monkeypatch.setattr(shutil, "which", lambda t: None)
    assert not _ult.ultron_agent.content_discovery("http://t.com")["success"]


def test_spa_crawl_graceful_no_playwright(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)   # force import failure
    r = _ult.ultron_agent.spa_crawl("example.com")
    assert not r["success"] and "Playwright" in r["message"]


def test_scope_most_specific_wins(monkeypatch):
    monkeypatch.setattr(_ult, "_load_scope", lambda: {
        "in_scope": ["*.acme.com", "api.acme.io"],
        "out_of_scope": ["admin.acme.com", "*.staging.acme.com"]})
    assert _ult._in_scope("app.acme.com") == "in"
    assert _ult._in_scope("admin.acme.com") == "out"       # exact OOS beats *.acme.com
    assert _ult._in_scope("x.staging.acme.com") == "out"
    assert _ult._in_scope("evil.com") == "unknown"
    keep, drop = _ult.scope_filter(["app.acme.com", "admin.acme.com", "blog.acme.com"])
    assert "admin.acme.com" in drop and "app.acme.com" in keep

def test_bugbounty_refuses_out_of_scope(monkeypatch):
    monkeypatch.setattr(_ult, "_load_scope", lambda: {"in_scope": ["*.acme.com"], "out_of_scope": ["admin.acme.com"]})
    r = _ult.ultron_agent.bug_bounty("admin.acme.com")
    assert not r["success"] and "OUT OF SCOPE" in r["message"]


def test_setup_scope_and_roe_filter(monkeypatch, tmp_path):
    import os, json
    monkeypatch.setattr(_ult, "parse_scope", lambda t: {
        "in_scope_domains": ["*.acme.com"], "out_of_scope_domains": [],
        "in_scope_types": ["sqli"], "out_of_scope_types": ["self-xss", "open-ports"],
        "rate_limit_rps": 5, "max_concurrent": 5, "rules": ["use own accounts"]})
    # isolate data/ via cwd
    monkeypatch.chdir(tmp_path)
    os.makedirs("data", exist_ok=True)
    r = _ult.ultron_agent.setup_scope("a long enough policy text to clear the length guard here")
    assert r["success"]
    assert json.load(open("data/roe.json"))["rate_limit_rps"] == 5
    g_xss = _ult.ultron_agent._validate_finding(
        {"template": "self-xss-x", "severity": "high", "url": "http://x/p?id=1", "validated": True, "cve": ""}, {})
    g_sqli = _ult.ultron_agent._validate_finding(
        {"template": "sqli-error-based", "severity": "high", "url": "http://x/p?id=1", "validated": True, "cve": ""}, {})
    assert not g_xss["report"] and g_sqli["report"]


# ── friday-recon CLI dogfood regressions (2026-06-27) ──────────────────────────
import agents.ultron.ultron_agent as _ult


def test_cli_output_cp1252_printable():
    """Every method message the CLI prints (_run -> print) must encode to cp1252 —
    a non-cp1252 char crashes a real Windows console. Regression for the → / ✓✗★⚠ fixes."""
    U = _ult.ultron_agent
    msgs = []
    # report builder (had → and ★/⚠/✓)
    f = [{"template": "sqli-error-based", "severity": "high", "url": "http://t/p?id=1",
          "cve": None, "validated": True, "evidence": "db error", "repro": ["x"]}]
    f[0]["_gate"] = U._validate_finding(f[0], {})
    msgs.append(U._format_bb_report("t", f, {}, {"urls": ["http://t/p?id=1"]}, True))
    msgs.append("\n".join(U._build_test_plan("t", f, {"urls": ["http://t/p?id=1"]})))
    msgs.append(U.find_programs().get("message", ""))            # had ★
    msgs.append(U.defensive_scan().get("message", ""))
    msgs.append(U.session_list().get("message", ""))
    for m in msgs:
        m.encode("cp1252")          # raises if any non-cp1252 char -> the console-crash bug


def test_cli_scope_setup_missing_file_is_graceful():
    """`cli.py scope-setup /no/such/file` must print a clean error + exit 1, not a traceback."""
    import subprocess, sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run([sys.executable, "cli.py", "scope-setup", "/no/such/policy.txt"],
                       cwd=root, capture_output=True, env=dict(os.environ, JARVIS_CI="1"), timeout=60)
    assert b"Traceback" not in p.stderr, "scope-setup leaked a traceback on a missing file"
    assert p.returncode == 1


def test_f1_live_capture_shared_schema():
    """F1 port: live_capture builds the SAME inventory schema as burp_ingest (by construction)."""
    from core import live_capture as lc, burp_ingest as bi
    recs = [{"url": "http://t.local/rest/basket/6?x=1", "method": "GET", "status": 200,
             "request": "GET /rest/basket/6?x=1 HTTP/1.1\r\nCookie: sid=9\r\n"
                        "Authorization: Bearer eyJhbGci.def12345678.ghi90\r\n\r\n",
             "response": "HTTP/1.1 200\r\nServer: nginx\r\nContent-Type: application/json\r\n\r\n{}"}]
    assert lc.build_from_records(recs) == bi._build_inventory(recs)
    assert lc.id_record_urls(recs) == ["http://t.local/rest/basket/6?x=1"]


def test_f1_capture_roundtrip_and_register():
    """F1 port: save/load a capture + auto-register the 'captured' principal from traffic."""
    from core import live_capture as lc, session_manager as sm
    host = "f1recon.local"
    try:
        recs = [{"url": f"http://{host}/rest/basket/6", "method": "GET", "status": 200,
                 "request": "GET /rest/basket/6 HTTP/1.1\r\nCookie: sessionid=SECRET; a=b\r\n\r\n",
                 "response": "HTTP/1.1 200\r\n\r\n{}"}]
        inv = lc.save_capture(host, recs)
        assert any("/rest/basket/6" in u for u in inv.get("urls", []))
        assert lc.load_capture(host) == inv
        assert "sessionid=SECRET" in (sm.get("captured") or {}).get("cookie", "")
    finally:
        sm.delete("captured")
        f = lc._host_file(host)
        if os.path.exists(f):
            os.remove(f)


def test_f3_evidence_object_parity():
    """F3 parity: canonical Evidence Object (versioned, CWE + preliminary CVSS + curl)."""
    from core import evidence
    o = evidence.build({"template": "sqli-error-based", "severity": "high", "url": "http://t/s",
                        "evidence": "db error", "repro": ["inject '"], "validated": True,
                        "_gate": {"tier": "P2", "confidence": "reproduced"}}, "t")
    assert o["schema_version"] == 1
    assert o["cwe"]["id"] == "CWE-89"
    assert o["cvss"]["preliminary"] is True
    assert evidence.lint(o) == []
    md = evidence.to_markdown(o)
    assert "CWE-89" in md and "CVSS 3.1" in md and "curl" in md


def test_f4_timeline_recorder_parity(tmp_path):
    """F4 parity: pure recorder — events + step() timing, immutable versioned
    timeline.json persisted/loadable, status derived from event outcomes."""
    from core import timeline
    timeline._RUNS_DIR = str(tmp_path)
    tl = timeline.start_run("t.com")
    assert tl.status == "running" and tl.run_id
    tl.record_event("subfinder", tool="subfinder", outputs={"domains": 143})
    with tl.step("httpx", inputs={"target": "t.com"}) as ev:
        ev["outputs"] = {"alive": 121}
    # step() records the failure then re-raises (pipeline behaviour unchanged)
    import pytest
    with pytest.raises(RuntimeError):
        with tl.step("nuclei"):
            raise RuntimeError("boom")
    tl.finish()
    assert len(tl.events) == 3
    assert tl.status == "partial"          # ok + failed mix
    back = timeline.load(tl.run_id)
    assert back and back["schema_version"] == 1
    assert back["events"][2]["status"] == "failed" and "boom" in back["events"][2]["error"]
    assert back["events"][1]["outputs"]["alive"] == 121
    assert back["events"][1]["duration_ms"] is not None
    assert tl.run_id in timeline.list_runs()
    view = timeline.render(tl.run_id)
    assert "t.com" in view and "httpx" in view and "✗" in view
    assert tl.run_id[:8] in timeline.render_list()
    # artifact persistence (debugging superpower / replay input)
    import os, json
    art = tl.write_artifact("endpoints.json", ["http://t.com/a"])
    assert art and os.path.exists(art["path"])
    assert json.load(open(art["path"], encoding="utf-8")) == ["http://t.com/a"]


def test_f4_bug_bounty_threads_timeline(tmp_path):
    """F4 parity: bug_bounty threads the execution timeline — run_id + stage events."""
    from core import timeline
    from agents.ultron import ultron_agent as _ult
    U = _ult.ultron_agent
    timeline._RUNS_DIR = str(tmp_path)
    stubs = {"full_pipeline": lambda *a, **k: {"success": True, "data":
                {"urls": ["http://t.example/a?id=1"], "post_endpoints": [],
                 "sections": {"nuclei": "", "httpx": ""}}},
             "_probe_injection": lambda *a, **k: [
                {"template": "sqli-error-based", "severity": "high", "url": "http://t.example/a?id=1",
                 "cve": "", "evidence": "db error", "repro": ["x"]}],
             "_probe_post": lambda *a, **k: [],
             "_probe_path_params": lambda *a, **k: [],
             "_probe_stored_xss": lambda *a, **k: [],
             "save_report": lambda *a, **k: "",
             "collect_evidence": lambda *a, **k: {"success": True, "data": {}}}
    for name, fn in stubs.items():
        setattr(U, name, fn)
    try:
        r = U.bug_bounty("t.example", force=True)
        rid = r["data"].get("run_id")
        assert rid
        tl = timeline.load(rid)
        assert tl and tl["schema_version"] == 1
        by_step = {e["step"]: e for e in tl["events"]}
        for s in ("recon", "probe", "idor", "gate", "evidence"):
            assert s in by_step, f"missing {s} in {list(by_step)}"
        assert tl["status"] in ("ok", "partial", "failed")
        # rich inputs (replay needs target) + persisted artifacts
        assert by_step["recon"]["inputs"].get("target") == "t.example"
        import os
        for art_name in ("endpoints.json", "findings.json"):
            assert os.path.exists(os.path.join(str(tmp_path), rid, art_name)), art_name
    finally:
        for name in stubs:
            try:
                delattr(U, name)
            except Exception:
                pass


def test_f4_package_parity(tmp_path):
    """F4 parity: build_package zips a run — timeline + artifacts + report + evidence."""
    import os, zipfile
    from core import timeline, package
    timeline._RUNS_DIR = str(tmp_path)
    tl = timeline.start_run("t.example")
    tl.write_artifact("endpoints.json", ["http://t.example/a"])
    tl.write_artifact("findings.json", [{"template": "sqli"}])
    reports = os.path.join(str(tmp_path), "reports")
    os.makedirs(os.path.join(reports, "evidence"), exist_ok=True)
    report = os.path.join(reports, "bugbounty_t.example.md")
    open(report, "w", encoding="utf-8").write("# Report")
    open(os.path.join(reports, "evidence", "01_sqli.json"), "w", encoding="utf-8").write("{}")
    tl.record_event("evidence", artifacts=[{"name": "bugbounty_t.example.md",
                                            "path": report, "kind": "report"}])
    tl.finish()
    r = package.build_package(tl.run_id)
    assert r["success"] and os.path.exists(r["data"]["path"])
    with zipfile.ZipFile(r["data"]["path"]) as z:
        names = z.namelist()
    for want in ("timeline.json", "endpoints.json", "findings.json",
                 "bugbounty_t.example.md", "evidence/01_sqli.json"):
        assert want in names, f"missing {want} in {names}"
    assert not package.build_package("nope")["success"]


def test_f4_replay_parity(tmp_path):
    """F4 parity: replay reruns a recorded run — full hunt from target, per-step probe from
    the persisted endpoints artifact, refuses unknown/missing runs."""
    from core import timeline, replay
    from agents.ultron import ultron_agent as _ult
    U = _ult.ultron_agent
    timeline._RUNS_DIR = str(tmp_path)
    tl = timeline.start_run("t.example")
    tl.write_artifact("endpoints.json", ["http://t.example/a?id=1"])
    tl.finish()
    stubs = {"bug_bounty": lambda *a, **k: {"success": True, "data": {"run_id": "NEWRUN", "report": "r"}},
             "_probe_injection": lambda urls, **k: [{"template": "sqli", "url": urls[0]}] if urls else [],
             "_probe_path_params": lambda *a, **k: [],
             "_probe_stored_xss": lambda *a, **k: [],
             "_probe_post": lambda *a, **k: []}
    for name, fn in stubs.items():
        setattr(U, name, fn)
    try:
        full = replay.replay(tl.run_id)
        assert full["success"] and full["data"].get("new_run_id") == "NEWRUN"
        probe = replay.replay(tl.run_id, "probe")
        assert probe["success"] and len(probe["data"]["findings"]) == 1
        bogus = replay.replay(tl.run_id, "nope")
        assert not bogus["success"] and "not replayable" in bogus["message"]
        missing = replay.replay("does-not-exist")
        assert not missing["success"] and "No run" in missing["message"]
    finally:
        for name in stubs:
            try:
                delattr(U, name)
            except Exception:
                pass
