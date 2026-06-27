#!/usr/bin/env python
"""
Seed the playbook from public, content-first methodology writeups (Option A).

Source: KathanP19/HowToHunt — per-class bug-bounty methodology in raw markdown
(no JS, no bot-block, no ToS scrape problem, unlike HackerOne report pages). Each
file is full technique text → ingest_writeup distils it into data/playbook.json
(gitignored, local) with source="writeup", verify=True.

Re-runnable: playbook.add novelty-dedups, so repeat runs only add what's new.
Usage:  python scripts/ingest_writeups.py
"""
import os, sys, time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.ultron.ultron_agent import ultron_agent as U
from core import playbook as pb

RAW = "https://raw.githubusercontent.com/KathanP19/HowToHunt/master/"
# second source: PayloadsAllTheThings — payload-DENSE per-class README markdown
PATTH = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/"
PATTH_PATHS = [
    "Command Injection/README.md", "SQL Injection/README.md", "NoSQL Injection/README.md",
    "XSS Injection/README.md", "Server Side Request Forgery/README.md", "Open Redirect/README.md",
    "File Inclusion/README.md", "Directory Traversal/README.md", "CORS Misconfiguration/README.md",
    "CRLF Injection/README.md", "GraphQL Injection/README.md", "JSON Web Token/README.md",
    "OAuth Misconfiguration/README.md", "Insecure Deserialization/README.md", "Mass Assignment/README.md",
    "Prototype Pollution/README.md", "Request Smuggling/README.md", "Server Side Template Injection/README.md",
    "XXE Injection/README.md", "LDAP Injection/README.md", "Account Takeover/README.md",
    "Business Logic Errors/README.md", "Race Condition/README.md", "Upload Insecure Files/README.md",
]

# one or two primary methodology files per class we carry in the playbook
PATHS = [
    "API_Testing/Reverse_Engineer_an_API.md",
    "Account_Takeovers_Methodologies/Account_Takeovers_Methods.md",
    "Authentication_Bypass/2FA_Bypasses.md",
    "CORS/CORS.md",
    "CORS/CORS_Bypasses.md",
    "CSRF/CSRF.md",
    "File_Upload/file_upload.md",
    "GraphQL/GraphQL.md",
    "Host-Header/Host-Header.md",
    "HTTP_Desync/http_desync.md",
    "IDOR/IDOR.md",
    "JWT/JWT.md",
    "OAuth/OAuth 2.0 Hunting Methodology.md",
    "Open_Redirection/Open_Redirection_Bypass.md",
    "Parameter_Pollution/Parameter_Pollution_in_social_sharing_buttons.md",
    "Password_Reset_Functionality/Top_5_Password_Reset_Bugs.md",
    "Race_Condition/race_conditions.md",
    "SQLi/SQL_Injection.md",
    "SSRF/SSRF.md",
    "SSRF/Blind_SSRF.md",
    "SSTI/SSTI.md",
    "Subdomain_Takeover/Sub_or_top_level_domain_takeover.md",
    "XSS/XSS_Bypass.md",
]


def main():
    import sys as _sys
    # `python scripts/ingest_writeups.py patth` runs the PayloadsAllTheThings batch
    which = _sys.argv[1] if len(_sys.argv) > 1 else "howtohunt"
    base, paths = (PATTH, PATTH_PATHS) if which == "patth" else (RAW, PATHS)
    before = pb.stats()["total"]
    total_added = ok = 0
    for i, p in enumerate(paths, 1):
        url = base + quote(p)
        try:
            r = U.ingest_writeup(url)
        except Exception as e:
            print(f"[{i:2}/{len(paths)}] ERR {p}: {str(e)[:60]}")
            continue
        d = r.get("data", {})
        added = d.get("added", 0)
        if r.get("success") and added is not None:
            ok += 1
            total_added += added or 0
            print(f"[{i:2}/{len(paths)}] +{added or 0:2}  {p}")
        else:
            print(f"[{i:2}/{len(paths)}] --  {p}  ({r.get('message','')[:50]})")
        time.sleep(1.0)        # be polite to raw.githubusercontent
    s = pb.stats()
    print(f"\nDONE: {ok}/{len(paths)} pages ingested, +{total_added} techniques.")
    print(f"PLAYBOOK: {before} -> {s['total']} | validated {s['validated']} | "
          f"verify {s['verify_needed']} | classes {s['classes']}")


if __name__ == "__main__":
    main()
