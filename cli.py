#!/usr/bin/env python3
"""
friday-recon — local-first AI-assisted recon / bug-bounty CLI.

The offensive-security core of the FRIDAY (JARVIS) assistant, extracted into a
focused, dependency-light tool. Same engine (Ultron), no Flask/HUD/voice. Runs
fully local against Ollama; recon tools optional (degrade gracefully).

    python cli.py scan example.com
    python cli.py cve log4j
    python cli.py bugbounty example.com
    python cli.py burp export.xml
    python cli.py kb "how do I test for subdomain takeover"
    python cli.py github-hunt acme
    python cli.py profile example.com

Authorized targets only.
"""
import sys
import os
import argparse

# cp1252 console guard (the root fix) — never let a non-ASCII char (emoji, arrow, or a
# real target's accented title / payload / writeup text) crash output on a Windows console.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Enable ANSI colour on Windows terminals (no-op elsewhere).
if os.name == "nt":
    os.system("")

__version__ = "1.0.0"

# ── ANSI colours ──
_G  = "\033[92m"   # bright green
_DG = "\033[32m"   # green
_C  = "\033[96m"   # cyan
_Y  = "\033[93m"   # yellow
_DIM = "\033[90m"  # grey
_B  = "\033[1m"
_R  = "\033[0m"    # reset

_ART = r"""
███████╗██████╗ ██╗██████╗  █████╗ ██╗   ██╗
██╔════╝██╔══██╗██║██╔══██╗██╔══██╗╚██╗ ██╔╝
█████╗  ██████╔╝██║██║  ██║███████║ ╚████╔╝
██╔══╝  ██╔══██╗██║██║  ██║██╔══██║  ╚██╔╝
██║     ██║  ██║██║██████╔╝██║  ██║   ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   """


def _ollama_status() -> str:
    """Quick non-blocking check — is the local reasoning engine up?"""
    import socket
    try:
        with socket.create_connection(("localhost", 11434), timeout=0.4):
            return f"{_G}●{_R} Engine: Ollama qwen2.5 {_G}online{_R}"
    except Exception:
        return f"{_DIM}●{_R} Engine: Ollama {_Y}offline{_R} {_DIM}(reasoning degrades gracefully){_R}"


def print_banner() -> None:
    print(f"{_B}{_G}{_ART}{_R}")
    print(f"   {_DG}R E C O N{_R}  {_DIM}—{_R}  Local-first AI recon & bug-bounty toolkit  {_DIM}v{__version__}{_R}\n")
    print(f"   {_DIM}Maintainer:{_R} Kiran {_DIM}·{_R} {_C}https://github.com/Kirankk7/friday-recon{_R}")
    print(f"   {_Y}⚠ Authorized targets only — Ultron core, same engine as JARVIS{_R}")
    print(f"   {_ollama_status()}\n")
    print(f"{_B} Available commands:{_R}")
    rows = [
        ("recon <t>",      "full pipeline: nmap → subfinder → httpx → nuclei → katana"),
        ("bugbounty <t>",  "hunt → validation gate → platform-ready PoC report"),
        ("idor <url>",     "cross-account IDOR/BOLA oracle (owner vs attacker)"),
        ("graphql <url>",  "introspection + privileged-mutation hunt"),
        ("discover <t>",   "content discovery — brute-force hidden paths/dirs"),
        ("kb \"<q>\"",       "methodology knowledge base (grounded, cited)"),
        ("threat-intel <i>","IOC reputation across feeds (IP/domain/URL/hash)"),
    ]
    for cmd, desc in rows:
        print(f"   {_G}{cmd:<18}{_R}{_DIM}{desc}{_R}")
    print(f"   {_DIM}…and 18 more — run{_R} {_C}python cli.py -h{_R} {_DIM}for the full list.{_R}\n")
    print(f"{_DG} ▸ python cli.py <command> <target>{_R}\n")


from agents.ultron.ultron_agent import ultron_agent


def _run(action: str, **params) -> int:
    res = ultron_agent.run("", action, params)
    msg = res.get("message", "") if isinstance(res, dict) else str(res)
    print(msg)
    return 0 if (isinstance(res, dict) and res.get("success", True)) else 1


def main() -> int:
    # No command → show the banner + menu (like a splash), then exit clean.
    if len(sys.argv) == 1 or sys.argv[1] in ("banner", "--banner"):
        print_banner()
        return 0

    p = argparse.ArgumentParser(prog="friday-recon",
                                description="Local AI-assisted recon / bug-bounty toolkit (Ultron core).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, help_, *args):
        sp = sub.add_parser(name, help=help_)
        for a in args:
            sp.add_argument(a)
        return sp

    sp = sub.add_parser("scan", help="Nmap port scan")
    sp.add_argument("target"); sp.add_argument("--type", default="basic")
    sp_rc = add("recon", "Full recon pipeline (nmap→subfinder→httpx→nuclei→katana)", "target"); sp_rc.add_argument("--force", action="store_true"); sp_rc.add_argument("--discover", action="store_true", help="also brute hidden paths (ffuf/gobuster) — slower/noisier")
    add("cve", "Search NVD for CVEs by keyword", "keyword")
    sp_bb = add("bugbounty", "Full bug-bounty workflow → validated PoC report", "target"); sp_bb.add_argument("--force", action="store_true"); sp_bb.add_argument("--discover", action="store_true", help="also brute hidden paths (ffuf/gobuster) — slower/noisier")
    sp_bb.add_argument("--owner", default=""); sp_bb.add_argument("--attacker", default="")   # IDOR oracle principals (else auto from 2 sessions)
    add("burp", "Ingest a Burp HTTP-history XML export → endpoint inventory", "path")
    add("scope-setup", "Parse a pasted program policy (text file) → set in/out scope + rules", "policyfile")
    add("kb", "Ask the bug-bounty methodology knowledge base", "query")
    add("github-hunt", "Enumerate an org/user's repos + flag secret-prone files", "org")
    add("profile", "Show the stored profile for a target", "host")
    add("evidence", "Re-probe a finding URL and capture evidence", "url")
    add("discover", "Brute-force hidden paths/dirs (ffuf/gobuster)", "target")
    add("spacrawl", "Render a JS/SPA in headless Chromium → capture API surface", "target")
    add("crawl", "Multi-page BFS crawl → full parameterized-URL surface across sub-pages", "target")
    add("playbook", "Recall attack techniques from the playbook (proven + KB + PortSwigger)", "query")
    add("ingest-writeup", "Learn a public bug-bounty writeup → playbook (local)", "url")
    add("ingest-feed", "Ingest a writeup-index page → learn each article", "url")
    add("threat-intel", "Aggregate IOC reputation (IP/domain/URL/hash) across feeds", "ioc")
    add("graphql", "Hunt a GraphQL endpoint (introspection + privileged-mutation inventory)", "url")
    add("jwt", "Analyze a JWT — alg:none/weak-HS/jku-SSRF/kid/exp/claims (deterministic, no cracking)", "token")
    add("takeover", "Subdomain-takeover check (dangling-service fingerprints; host, comma-list, or @file)", "hosts")
    add("cors", "CORS misconfig probe (Origin reflection + credentials) over a target + its crawled URLs", "target")
    add("secrets", "Scan crawled JS for hard-coded keys + probe exposed files (.git/.env/.DS_Store)", "target")
    sp_oa = add("oast", "Confirm a BLIND class via an out-of-band callback (--kind ssrf|cmdi|xxe)", "url")
    sp_oa.add_argument("--kind", default="ssrf", choices=["ssrf", "cmdi", "xxe"])
    sp_oa.add_argument("--param", default="url"); sp_oa.add_argument("--wait", type=float, default=3.0)
    sp_xc = add("xss-confirm", "Confirm reflected XSS by EXECUTION in a headless browser (candidate->confirmed)", "url")
    sp_xc.add_argument("--param", required=True); sp_xc.add_argument("--cookie", default="")
    sp_se = add("session-set", "Register a principal for authz testing (cookie)", "name", "cookie")
    sub.add_parser("sessions", help="List authz-test sessions")
    sp_id = add("idor", "IDOR/BOLA check: owner vs attacker (anon control)", "url")
    sp_id.add_argument("--owner", default="userA"); sp_id.add_argument("--attacker", default="userB")
    # opt-in write-BOLA (mutates then reverts a benign field — authorized own-accounts only)
    sp_wb = add("write-bola", "Write-BOLA: attacker mutates owner's field, verify+revert (benign fields only)", "url")
    sp_wb.add_argument("--field", default="email"); sp_wb.add_argument("--owner", default="userA")
    sp_wb.add_argument("--attacker", default="userB"); sp_wb.add_argument("--method", default="PUT")
    sp_wb.add_argument("--verify-url", default="", dest="verify_url")
    # Auth Matrix (v1.3) — endpoint x principal (BFLA + BOLA). Opt-in; set principals via session-set.
    sp_am = add("auth-matrix", "Auth Matrix: endpoint x principal -> BFLA + BOLA (set sessions first)", "target")
    sp_am.add_argument("--owner", default=""); sp_am.add_argument("--attacker", default="")
    sp_am.add_argument("--write", action="store_true", help="also opt-in write-BOLA (verify+revert, benign fields)")
    sub.add_parser("targets", help="List profiled targets")
    sub.add_parser("scope", help="Show the current in/out-of-scope rules (data/scope.json)")
    sub.add_parser("defensive", help="Blue-team host scan (new ports / suspicious procs)")
    sub.add_parser("wordlist", help="List bundled wordlists").add_argument("kind", nargs="?", default="")
    # F1 — live-capture proxy
    sub.add_parser("proxy", help="Live-capture proxy → data/capture/<host>.json (needs: pip install mitmproxy)").add_argument("--port", type=int, default=8081)
    add("capture", "Show the captured endpoint inventory for a host", "host")
    sp_sc = add("scan-captured", "IDOR/BOLA across captured object-id endpoints (owner=captured)", "host")
    sp_sc.add_argument("--attacker", default="userB")
    # F4 — execution timeline (read side)
    sp_tl = sub.add_parser("timeline", help="Show a run's execution timeline (no arg = list recent runs)")
    sp_tl.add_argument("run_id", nargs="?", default="")
    # F4 — replay a recorded run (reruns an ACTIVE scan on the recorded target)
    sp_rp = sub.add_parser("replay", help="Rerun a recorded run (--step full|recon|probe)")
    sp_rp.add_argument("run_id")
    sp_rp.add_argument("--step", default="full")
    # F4 — zip a recorded run into a submission package
    sp_pk = sub.add_parser("package", help="Zip a recorded run (timeline+artifacts+report+evidence) into a submission")
    sp_pk.add_argument("run_id")

    a = p.parse_args()
    c = a.cmd
    if c == "scan":        return _run("nmap_scan", target=a.target, scan_type=a.type)
    if c == "recon":       return _run("full_recon", target=a.target, force=getattr(a,"force",False), discover=getattr(a,"discover",False))
    if c == "cve":         return _run("search_cve", keyword=a.keyword)
    if c == "bugbounty":   return _run("bug_bounty", target=a.target, force=getattr(a,"force",False), owner=a.owner, attacker=a.attacker, discover=getattr(a,"discover",False))
    if c == "burp":        return _run("ingest_burp", path=a.path)
    if c == "scope-setup":
        try:
            _txt = open(a.policyfile, encoding="utf-8").read()
        except OSError as e:
            print(f"Can't read policy file '{a.policyfile}': {e}"); return 1
        return _run("setup_scope", text=_txt)
    if c == "kb":          return _run("kb_methodology", query=a.query)
    if c == "github-hunt": return _run("github_hunt", org=a.org)
    if c == "profile":     return _run("target_profile", target=a.host)
    if c == "evidence":    return _run("collect_evidence", url=a.url)
    if c == "discover":    return _run("content_discovery", target=a.target)
    if c == "spacrawl":    return _run("spa_crawl", target=a.target)
    if c == "crawl":       return _run("crawl_site", target=a.target)
    if c == "playbook":    return _run("playbook_recall", query=a.query)
    if c == "ingest-writeup": return _run("ingest_writeup", url=a.url)
    if c == "ingest-feed": return _run("ingest_feed", url=a.url)
    if c == "threat-intel": return _run("threat_intel", ioc=a.ioc)
    if c == "graphql":     return _run("graphql_hunt", url=a.url)
    if c == "jwt":
        from agents.ultron.ultron_agent import ultron_agent as U
        r = U.jwt_analyze(a.token)
        print(r.get("message", ""))
        for f in r.get("data", {}).get("findings", []):
            print(f"  [{f['severity'].upper()}] {f['template']}: {f['evidence'][:130]}")
        return 0 if r.get("success") else 1
    if c == "takeover":
        from agents.ultron.ultron_agent import ultron_agent as U
        import os as _os
        hosts = open(a.hosts[1:], encoding="utf-8").read() if a.hosts.startswith("@") and _os.path.exists(a.hosts[1:]) else a.hosts
        r = U.subdomain_takeover(hosts)
        print(r.get("message", ""))
        for f in r.get("data", {}).get("findings", []):
            print(f"  [{f['severity'].upper()}] {f['url']}: {f['evidence'][:130]}")
        return 0 if r.get("success") else 1
    if c == "cors":
        from agents.ultron.ultron_agent import ultron_agent as U
        base = a.target if a.target.startswith("http") else "https://" + a.target
        urls = [base]
        try:
            urls += U.crawl_site(a.target).get("data", {}).get("urls", [])
        except Exception:
            pass
        r = U.cors_check(urls)
        print(r.get("message", ""))
        for f in r.get("data", {}).get("findings", []):
            print(f"  [{f['severity'].upper()}] {f['url']}: {f['evidence'][:130]}")
        return 0 if r.get("success") else 1
    if c == "secrets":
        from agents.ultron.ultron_agent import ultron_agent as U
        r = U.secret_scan(a.target)
        print(r.get("message", ""))
        for f in r.get("data", {}).get("findings", []):
            print(f"  [{f['severity'].upper()}] {f['template']}: {f['url']}")
        return 0 if r.get("success") else 1
    if c == "oast":       return _run("oast_probe", url=a.url, param=a.param, kind=a.kind, wait=a.wait)
    if c == "xss-confirm": return _run("xss_confirm", url=a.url, param=a.param, cookie=a.cookie)
    if c == "session-set": return _run("session_set", name=a.name, cookie=a.cookie)
    if c == "sessions":    return _run("session_list")
    if c == "idor":        return _run("idor_check", url=a.url, owner=a.owner, attacker=a.attacker)
    if c == "write-bola":  return _run("write_bola_check", url=a.url, field=a.field, owner=a.owner, attacker=a.attacker, method=a.method, verify_url=a.verify_url)
    if c == "auth-matrix":
        from agents.ultron.ultron_agent import ultron_agent as U
        from core import target_profiles as tp
        host = a.target.split("//")[-1].split("/")[0]
        eps = list(tp._load().get(tp._norm(host), {}).get("endpoints", []))      # burp/recon/prior-crawl inventory
        base = a.target if a.target.startswith("http") else "http://" + a.target
        try:
            eps += U.crawl_site(a.target).get("data", {}).get("urls", [])          # + live parameterized surface
        except Exception:
            pass
        if base not in eps:
            eps.append(base)
        r = U.auth_matrix(eps, owner=a.owner, attacker=a.attacker, write=a.write)
        print(r.get("message", ""), "\n")
        print(r["data"]["table_md"])
        for f in r["data"].get("findings", []):
            print(f"  [{f['template']}] {f['url']}")
        return 0 if r.get("success") else 1
    if c == "targets":     return _run("list_targets")
    if c == "scope":       return _run("scope_status")
    if c == "defensive":   return _run("defensive_scan")
    if c == "wordlist":    return _run("kb_wordlist", kind=a.kind)
    if c == "proxy":
        from core.live_capture import _run_proxy
        return _run_proxy(a.port)
    if c == "capture":
        from core import live_capture as lc
        inv = lc.load_capture(a.host)
        if not inv:
            print(f"No capture for {a.host}. Run 'proxy', browse the target, then retry."); return 1
        print(f"{a.host}: {len(inv.get('endpoints', []))} endpoints, "
              f"{len(inv.get('params', []))} params, tags={list(inv.get('tags', {}).keys())}")
        return 0
    if c == "scan-captured":
        from core import live_capture as lc
        r = lc.scan_captured(a.host, attacker=a.attacker)
        print(r.get("message", "")); return 0 if r.get("success") else 1
    if c == "timeline":
        from core import timeline as tl
        print(tl.render(a.run_id) if a.run_id else tl.render_list())
        return 0
    if c == "replay":
        from core import replay
        r = replay.replay(a.run_id, step=a.step)
        print(r.get("message", ""))
        nid = r.get("data", {}).get("new_run_id")
        if nid:
            print(f"new run: {nid}")
        return 0 if r.get("success") else 1
    if c == "package":
        from core import package
        r = package.build_package(a.run_id)
        print(r.get("message", ""))
        return 0 if r.get("success") else 1
    p.print_help(); return 1


if __name__ == "__main__":
    raise SystemExit(main())
