# friday-recon

![tests](https://github.com/Kirankk7/friday-recon/actions/workflows/test.yml/badge.svg)

A **local-first, AI-assisted recon & bug-bounty toolkit** — the offensive-security core
of the [FRIDAY (JARVIS)](https://github.com/Kirankk7/FRIDAY) assistant, extracted into a
focused, dependency-light CLI. Same engine (the *Ultron* agent), no Flask / HUD / voice.
Runs fully on a local LLM via [Ollama](https://ollama.com) — no cloud, no API keys for
reasoning. ~30 MB install, no GPU required.

> Authorized targets only. This is an offensive-security tool; see **[THREAT_MODEL.md](THREAT_MODEL.md)**.

---

## What it does

```
recon        nmap (scan diffing) · subfinder · httpx · katana · nuclei
intel        NVD CVE search · VirusTotal · CVE → asset correlation
bug bounty   full pipeline → 7-question validation gate (kills noise) → platform-ready PoC report
traffic      ingest a Burp Suite (Community) HTTP-history export → endpoint/param inventory
                + auto-tagging (JWT / GraphQL / API / auth-boundary / tech)
memory       per-target profiles (scans, findings, endpoints, typed intel, evidence) across hunts
evidence     re-probe a finding → capture confirmed request/response evidence for the report
authz        auth-matrix (endpoint × principal → BFLA + BOLA) · idor/bola oracle · jwt analyzer
confirm      OAST out-of-band (ssrf/cmdi/xxe) · headless-browser XSS execution · CORS · subdomain takeover
secrets      GitHub org/user repo hunt → flag secret-prone files → TruffleHog deep-scan
methodology  RAG over 87 real bug-bounty / OSINT methodology notes (local TF-IDF, cited)
fleet        180+ HackingTool index, gated to ~25 runnable (capability allowlist, offensive blocked)
blue-team    host monitor: baseline listening ports + processes, flag new/suspicious
```

## Install

```bash
pip install -r requirements.txt
ollama pull qwen2.5:7b          # local reasoning model
# optional recon binaries on PATH: nmap, subfinder, httpx, nuclei, katana
# optional: WSL or Docker for the 180+ HackingTool fleet
```

## Use

```bash
# recon
python cli.py scan example.com              # nmap port scan (with scan diffing)
python cli.py recon example.com [--discover] # full pipeline: nmap→subfinder→httpx→nuclei→katana→sitemap
                                            #   subfinder auto-apexes (www.x.com→x.com); sitemap.xml+robots
                                            #   paths always in the report; --discover adds ffuf/gobuster brute
python cli.py discover example.com          # content discovery (ffuf/gobuster), standalone
python cli.py spacrawl example.com          # render SPA → capture API surface
python cli.py crawl example.com             # multi-page BFS crawl → parameterized URLs

# bug bounty
python cli.py bugbounty example.com [--discover]  # full hunt → validated PoC report on your Desktop (--discover = +dir-brute)
python cli.py proxy --port 8081             # live-capture proxy (browse authed → inventory)
python cli.py capture example.com           # show the captured endpoint/param inventory
python cli.py scan-captured example.com     # IDOR/BOLA across captured object-id endpoints
python cli.py graphql https://t.com/graphql # GraphQL introspection + privileged-mutation hunt
python cli.py idor https://t.com/api/1 --owner userA --attacker userB   # read IDOR/BOLA check (owner vs attacker vs anon)
python cli.py write-bola https://t.com/api/user/1 --field email --owner userA --attacker userB [--verify-url <read-url>]
                                            #   OPT-IN write-BOLA: attacker mutates owner's field, verify+revert (benign fields only)
python cli.py session-set bob <cookie>      # register a principal for authz testing
python cli.py sessions                      # list authz-test sessions
python cli.py evidence https://t.com/find   # re-probe a finding → capture evidence
python cli.py auth-matrix example.com       # Auth Matrix: endpoint × principal → BFLA + BOLA (set sessions first)
python cli.py jwt <token>                    # analyze a JWT — alg:none / weak-HS / jku-SSRF / kid / exp / claims (no cracking)
python cli.py cors https://t.com            # CORS misconfig probe (Origin reflection + credentials) over target + crawled URLs
python cli.py takeover sub.example.com      # subdomain-takeover check (dangling-service fingerprints; host, comma-list, or @file)
python cli.py secrets example.com           # scan crawled JS for hard-coded keys + probe exposed files (.git/.env/.DS_Store)
python cli.py xss-confirm https://t.com/r   # confirm reflected XSS by EXECUTION in a headless browser (candidate→confirmed)
python cli.py oast https://t.com --kind ssrf  # confirm a BLIND class via an out-of-band callback (ssrf|cmdi|xxe)

# F4 execution timeline (immutable run record → replay → submission package)
python cli.py timeline [<run_id>]           # list recent runs, or render one run's stage timeline
python cli.py replay <run_id> [--step full|recon|probe]   # rerun a recorded run (active scan)
python cli.py package <run_id>              # zip run (timeline+artifacts+report+evidence) → submission

# intel
python cli.py cve log4j                     # NVD CVE lookup
python cli.py threat-intel 1.2.3.4          # IOC reputation across feeds (IP/domain/URL/hash)
python cli.py kb "how do I test for subdomain takeover"   # methodology KB (cited)
python cli.py playbook "ssrf"               # recall attack techniques (proven + KB + PortSwigger)
python cli.py ingest-writeup <url>          # learn a public bug-bounty writeup → playbook (local)
python cli.py ingest-feed <url>             # ingest a writeup-index page → learn each article

# data / memory
python cli.py burp export.xml               # ingest Burp Community "Save items" XML
python cli.py github-hunt acme              # org repo secret hunt
python cli.py profile example.com           # what we know about a target, across hunts
python cli.py targets                       # list profiled targets
python cli.py scope                         # show in/out-of-scope rules
python cli.py scope-setup policy.txt        # parse a program policy → set scope
python cli.py defensive                     # blue-team host scan
python cli.py wordlist                      # list bundled wordlists
```

## Security posture

This is an offensive tool, so its own attack surface is documented openly in
**[THREAT_MODEL.md](THREAT_MODEL.md)** — trust boundaries, attacker model (indirect prompt
injection is primary), controls, and weaknesses with fixes. Hardening baked in: tool exec via
**argv arrays (no shell)**, a **capability allowlist** (offensive categories blocked, no
`--command/--force/--privileged`), and a **redirect- & encoding-aware SSRF guard**.

## Tests

```bash
pytest -q          # offline (no Ollama/network needed)
```
CI runs on every push (`.github/workflows/test.yml`).

## Attribution

Integration/orchestration work over excellent open components — credit to the authors:
AutoTune sampling (elder-plinius/G0DM0D3), SSRF guard pattern (OpenJarvis), HackingTool
index (Z4nzu/hackingtool via AKCodez), validation-gate discipline (shuvonsec/claude-bug-bounty),
and the methodology knowledge pack (SnailSploit/Claude-Red, hack-with-rohit, jivoi/awesome-osint,
sidhusec/Rudrascan). See `agents/ultron/knowledge/CREDITS.md`.
