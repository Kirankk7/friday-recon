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
python cli.py scan example.com
python cli.py recon example.com
python cli.py cve log4j
python cli.py bugbounty example.com         # → validated PoC report on your Desktop
python cli.py burp export.xml               # Burp Community "Save items" XML
python cli.py kb "how do I test for subdomain takeover"
python cli.py github-hunt acme
python cli.py profile example.com           # what we know about a target, across hunts
python cli.py evidence https://t.com/finding
python cli.py defensive                     # blue-team host scan
```

## Security posture

This is an offensive tool, so its own attack surface is documented openly in
**[THREAT_MODEL.md](THREAT_MODEL.md)** — trust boundaries, attacker model (indirect prompt
injection is primary), controls, and weaknesses with fixes. Hardening baked in: tool exec via
**argv arrays (no shell)**, a **capability allowlist** (offensive categories blocked, no
`--command/--force/--privileged`), and a **redirect- & encoding-aware SSRF guard**.

## Tests

```bash
pytest -q          # 17 tests, offline (no Ollama/network needed)
```
CI runs on every push (`.github/workflows/test.yml`).

## Attribution

Integration/orchestration work over excellent open components — credit to the authors:
AutoTune sampling (elder-plinius/G0DM0D3), SSRF guard pattern (OpenJarvis), HackingTool
index (Z4nzu/hackingtool via AKCodez), validation-gate discipline (shuvonsec/claude-bug-bounty),
and the methodology knowledge pack (SnailSploit/Claude-Red, hack-with-rohit, jivoi/awesome-osint,
sidhusec/Rudrascan). See `agents/ultron/knowledge/CREDITS.md`.
