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
    assert g["priority"] == gate.triage("high", "reproduced")

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


def test_probe_sqli_anomaly(monkeypatch):
    def _get(url, timeout=8, headers=None, allow_redirects=True):
        if "%27" in url:
            return _FakeResp("", 500)              # quote -> empty 500, no error string
        return _FakeResp("healthy page " * 100, 200)
    _patch_http(monkeypatch, _get)
    res = _ult.ultron_agent._probe_injection(["http://t.com/n.aspx?id=1"])
    sqli = [r for r in res if r["template"] == "sqli-error-based"]
    assert sqli and "500" in sqli[0]["evidence"]


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
    assert _ult._scope_check("foo.herokuapp.com")
    assert not _ult._scope_check("example.com")

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
        for s in ("recon", "probe", "gate", "evidence"):
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
