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
    def _get(url, timeout=8):
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
    def _get(url, timeout=8):
        if "%27" in url:
            return _FakeResp("", 500)              # quote -> empty 500, no error string
        return _FakeResp("healthy page " * 100, 200)
    _patch_http(monkeypatch, _get)
    res = _ult.ultron_agent._probe_injection(["http://t.com/n.aspx?id=1"])
    sqli = [r for r in res if r["template"] == "sqli-error-based"]
    assert sqli and "500" in sqli[0]["evidence"]
