#!/usr/bin/env python
"""
Canonicalize playbook class labels. Seeding (PortSwigger categories) and writeup
ingestion produced synonym labels for the same class (cross-site-scripting vs xss,
sql-injection vs sqli, ...), fragmenting token-based recall. This collapses the
obvious exact-synonyms to one short canonical label. Conservative — does NOT merge
genuinely-distinct broad categories (access-control, path-traversal stay).

Idempotent + re-runnable (run again after a fresh ingest). Mutates the gitignored
data/playbook.json in place.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import playbook as pb

ALIAS = {
    "cross-site-scripting": "xss", "xss-reflected": "xss", "xss-stored": "xss",
    "dom-based-vulnerabilities": "xss",
    "sql-injection": "sqli",
    "server-side-request-forgery-ssrf": "ssrf",
    "xml-external-entity-xxe-injection": "xxe",
    "cross-site-request-forgery-csrf": "csrf",
    "cross-origin-resource-sharing-cors": "cors",
    "nosql-injection": "nosqli", "nosql": "nosqli",
    "server-side-template-injection": "ssti",
    "http-host-header-attacks": "host-header",
    "os-command-injection": "cmd-injection", "os-cmd-injection": "cmd-injection",
    "race-conditions": "race",
    "graphql-api-vulnerabilities": "graphql",
    "oauth-authentication": "oauth",
    "insecure-deserialization": "deserialization",
    "file-upload-vulnerabilities": "file-upload",
    "business-logic-vulnerabilities": "business-logic", "bue": "business-logic",
    "authentication": "auth-bypass",
}


def main():
    doc = pb._load()
    changed = 0
    for e in doc["techniques"]:
        c = e.get("class", "")
        if c in ALIAS:
            e["class"] = ALIAS[c]; changed += 1
    pb._save(doc)
    s = pb.stats()
    print(f"normalized {changed} labels. classes {len(set(e['class'] for e in doc['techniques']))} | total {s['total']}")
    print("\ntop classes after:")
    for k, v in list(pb.classes().items())[:18]:
        print(f"  {v:3}  {k}")


if __name__ == "__main__":
    main()
