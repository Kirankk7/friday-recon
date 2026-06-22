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
    add("recon", "Full recon pipeline (nmap→subfinder→httpx→nuclei→katana)", "target")
    add("cve", "Search NVD for CVEs by keyword", "keyword")
    add("bugbounty", "Full bug-bounty workflow → validated PoC report", "target")
    add("burp", "Ingest a Burp HTTP-history XML export → endpoint inventory", "path")
    add("kb", "Ask the bug-bounty methodology knowledge base", "query")
    add("github-hunt", "Enumerate an org/user's repos + flag secret-prone files", "org")
    add("profile", "Show the stored profile for a target", "host")
    add("evidence", "Re-probe a finding URL and capture evidence", "url")
    add("discover", "Brute-force hidden paths/dirs (ffuf/gobuster)", "target")
    sub.add_parser("targets", help="List profiled targets")
    sub.add_parser("defensive", help="Blue-team host scan (new ports / suspicious procs)")
    sub.add_parser("wordlist", help="List bundled wordlists").add_argument("kind", nargs="?", default="")

    a = p.parse_args()
    c = a.cmd
    if c == "scan":        return _run("nmap_scan", target=a.target, scan_type=a.type)
    if c == "recon":       return _run("full_recon", target=a.target)
    if c == "cve":         return _run("search_cve", keyword=a.keyword)
    if c == "bugbounty":   return _run("bug_bounty", target=a.target)
    if c == "burp":        return _run("ingest_burp", path=a.path)
    if c == "kb":          return _run("kb_methodology", query=a.query)
    if c == "github-hunt": return _run("github_hunt", org=a.org)
    if c == "profile":     return _run("target_profile", target=a.host)
    if c == "evidence":    return _run("collect_evidence", url=a.url)
    if c == "discover":    return _run("content_discovery", target=a.target)
    if c == "targets":     return _run("list_targets")
    if c == "defensive":   return _run("defensive_scan")
    if c == "wordlist":    return _run("kb_wordlist", kind=a.kind)
    p.print_help(); return 1


if __name__ == "__main__":
    raise SystemExit(main())
