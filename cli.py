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

from agents.ultron.ultron_agent import ultron_agent


def _run(action: str, **params) -> int:
    res = ultron_agent.run("", action, params)
    msg = res.get("message", "") if isinstance(res, dict) else str(res)
    print(msg)
    return 0 if (isinstance(res, dict) and res.get("success", True)) else 1


def main() -> int:
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
    sp_rc = add("recon", "Full recon pipeline (nmap→subfinder→httpx→nuclei→katana)", "target"); sp_rc.add_argument("--force", action="store_true")
    add("cve", "Search NVD for CVEs by keyword", "keyword")
    sp_bb = add("bugbounty", "Full bug-bounty workflow → validated PoC report", "target"); sp_bb.add_argument("--force", action="store_true")
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
    sp_se = add("session-set", "Register a principal for authz testing (cookie)", "name", "cookie")
    sub.add_parser("sessions", help="List authz-test sessions")
    sp_id = add("idor", "IDOR/BOLA check: owner vs attacker (anon control)", "url")
    sp_id.add_argument("--owner", default="userA"); sp_id.add_argument("--attacker", default="userB")
    sub.add_parser("targets", help="List profiled targets")
    sub.add_parser("scope", help="Show the current in/out-of-scope rules (data/scope.json)")
    sub.add_parser("defensive", help="Blue-team host scan (new ports / suspicious procs)")
    sub.add_parser("wordlist", help="List bundled wordlists").add_argument("kind", nargs="?", default="")

    a = p.parse_args()
    c = a.cmd
    if c == "scan":        return _run("nmap_scan", target=a.target, scan_type=a.type)
    if c == "recon":       return _run("full_recon", target=a.target, force=getattr(a,"force",False))
    if c == "cve":         return _run("search_cve", keyword=a.keyword)
    if c == "bugbounty":   return _run("bug_bounty", target=a.target, force=getattr(a,"force",False))
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
    if c == "session-set": return _run("session_set", name=a.name, cookie=a.cookie)
    if c == "sessions":    return _run("session_list")
    if c == "idor":        return _run("idor_check", url=a.url, owner=a.owner, attacker=a.attacker)
    if c == "targets":     return _run("list_targets")
    if c == "scope":       return _run("scope_status")
    if c == "defensive":   return _run("defensive_scan")
    if c == "wordlist":    return _run("kb_wordlist", kind=a.kind)
    p.print_help(); return 1


if __name__ == "__main__":
    raise SystemExit(main())
