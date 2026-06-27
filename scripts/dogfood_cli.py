#!/usr/bin/env python
"""
friday-recon CLI dogfood harness (5-day intensive).

Runs each CLI verb as a SUBPROCESS with a forced cp1252 console (the real Windows
terminal contract), captures stdout/stderr/exit-code, and asserts per verb:
  (a) NO crash  — no Traceback / UnicodeEncodeError escaped to the user
  (b) cp1252-CLEAN output — stdout encodes to cp1252 (else the console would crash)
  (c) sane exit code — 0 (success) or 1 (handled failure), never a stack-trace exit

Prints a PASS/FAIL table; exits non-zero on any FAIL. A FAIL = a CLI bug to chase.
Some verbs need probe_lab on :7000 (run `python labs/probe_lab/app.py` from JARVIS).
Heavy/network verbs (recon, bugbounty, spacrawl, github-hunt) are skipped by default;
pass --heavy to include them.
"""
import os
import sys
import subprocess

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
L = "http://127.0.0.1:7000"

# (verb args...) — safe, fast, mostly-local. None = no extra arg.
VERBS = [
    ("kb", ["how to test sqli"]),
    ("playbook", ["jwt bypass"]),
    ("wordlist", []),
    ("targets", []),
    ("scope", []),
    ("sessions", []),
    ("defensive", []),
    ("session-set", ["userA", "uid=1"]),
    ("profile", ["127.0.0.1"]),
    ("cve", ["log4j"]),                       # NVD network
    ("threat-intel", ["8.8.8.8"]),           # THE cp1252 verdict-char test (DShield)
    ("crawl", [L]),
    ("graphql", [f"{L}/graphql"]),
    ("idor", [f"{L}/account?id=1"]),          # needs userA/userB sessions
    ("evidence", [f"{L}/render?tpl=hi"]),
    ("discover", [L]),
    # graceful-error inputs (bad file / bad url) — must NOT traceback
    ("burp", ["/no/such/file.xml"]),
    ("scope-setup", ["/no/such/policy.txt"]),
    ("ingest-writeup", ["http://127.0.0.1:9/dead"]),
    ("ingest-feed", ["not-a-url"]),
]
HEAVY = [
    ("recon", ["127.0.0.1"]),
    ("bugbounty", ["127.0.0.1"]),
    ("spacrawl", [L]),
    ("github-hunt", ["torvalds"]),
]


def run_verb(verb, args, timeout=90):
    env = dict(os.environ, PYTHONIOENCODING="cp1252", JARVIS_CI="1")
    try:
        p = subprocess.run([sys.executable, "cli.py", verb, *args], cwd=HERE, env=env,
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", "", None
    out = (p.stdout or b"").decode("cp1252", "replace")
    err = (p.stderr or b"").decode("utf-8", "replace")
    # crash detection
    crashed = "Traceback (most recent call last)" in err or "UnicodeEncodeError" in err
    # cp1252-clean: the raw stdout bytes must already be cp1252 (subprocess wrote with cp1252,
    # so a non-encodable char would have crashed the child -> Traceback in err). Double-check
    # by re-encoding the decoded text.
    try:
        out.encode("cp1252")
        cp_ok = True
    except Exception:
        cp_ok = False
    return ("CRASH" if crashed else ("BADCP" if not cp_ok else "ok")), out, err, p.returncode


def main():
    heavy = "--heavy" in sys.argv
    verbs = VERBS + (HEAVY if heavy else [])
    print(f"{'verb':16} {'status':8} {'exit':5} note")
    print("-" * 64)
    fails = 0
    for verb, args in verbs:
        # idor needs two sessions first
        if verb == "idor":
            run_verb("session-set", ["userB", "uid=2"])
        status, out, err, rc = run_verb(verb, args)
        ok = status == "ok" and rc in (0, 1)
        if not ok:
            fails += 1
        note = ""
        if status == "CRASH":
            note = (err.strip().splitlines() or [""])[-1][:48]
        elif status == "TIMEOUT":
            note = "exceeded timeout"
        elif status == "BADCP":
            note = "non-cp1252 char in output"
        elif rc not in (0, 1):
            note = f"weird exit code {rc}"
        print(f"{verb:16} {status:8} {str(rc):5} {note}")
    print("-" * 64)
    print(f"{len(verbs) - fails}/{len(verbs)} PASS" + ("" if not fails else f"  — {fails} FAIL"))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
