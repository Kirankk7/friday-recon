# FRIDAY — Threat Model

**Scope:** This document covers the security posture of FRIDAY (JARVIS), a local-first
multi-agent AI assistant with an embedded offensive-security toolkit (Ultron). It defines
trust boundaries, the asset inventory, the attacker model, the controls in place, and —
deliberately — the controls that are *not yet* adequate. Known weaknesses are listed openly
rather than hidden; this is a living document.

**Status:** Single-user local deployment. Not hardened for multi-tenant or internet-exposed
use. Do not expose `app.py` (Flask, default `:5000`) to an untrusted network.

---

## 1. System overview

```
Browser UI (HUD)  ──SSE──►  Flask (app.py)
                                │
                        brain.process_input_stream
                                │
                        cognitive_loop (route → execute → reflect)
                                │
                router ──► executor ──► agents (FRIDAY, Ultron, Vision, …)
                                                │
                                        ask_llm() ──► Ollama (local)
                                                │
                        Ultron ──► recon tools / HackingTool fleet (WSL/Docker)
```

The only intended human input channel is the local browser UI (or CLI voice loop).
Everything reachable downstream — the local LLM, the OS, the network, third-party tool
binaries, remote APIs — is treated as a separate trust zone.

---

## 2. Trust boundaries

| # | Boundary | Crossing | Trust direction |
|---|----------|----------|-----------------|
| B1 | User ↔ Flask app | HTTP/SSE on localhost | User input is **semi-trusted** (single local user, but free-form text reaches an LLM that emits tool calls) |
| B2 | App ↔ Local LLM (Ollama) | HTTP to `localhost:11434` | LLM output is **untrusted** — it can hallucinate tool calls, arguments, and targets |
| B3 | App ↔ OS / shell | `subprocess`, `os.system`, `os.startfile` | Anything crossing here is a privileged sink |
| B4 | App ↔ Security tool fleet | `bash -lc` via WSL/Docker (`ht_run.py`) | Arbitrary tool execution; highest-risk boundary |
| B5 | App ↔ Remote network | `requests`, Playwright, recon scans | Outbound SSRF surface + scanning-the-wrong-target risk |
| B6 | App ↔ Remote APIs | NVD, VirusTotal, football-data, GitHub | API keys at rest; response data is untrusted input |
| B7 | App ↔ Local filesystem | File agent, RAG indexer, memory stores | Read/summarize/patch of arbitrary local paths |

**Key insight for reviewers:** the dangerous boundary is **B2 → B3/B4**. The LLM is not a
trusted planner. A prompt-injected document, a poisoned API response, or a hallucination can
cause the model to emit a tool call with attacker-influenced arguments. Every control below
exists because LLM-emitted tool arguments must be treated as hostile.

---

## 3. Assets

| Asset | Where | Impact if compromised |
|-------|-------|----------------------|
| Host OS / shell | B3, B4 | Full RCE on the user's machine |
| API keys (NVD, VirusTotal, GitHub, n8n) | `.env` | Credential theft, abuse, billing |
| Internal network / cloud metadata | B5 | SSRF → lateral movement, IAM creds |
| Local files + memory stores | B7 | Data exfil, tampering of long-term memory |
| Scan authorization | B4, B5 | Unauthorized scanning = legal exposure |
| LLM context / memory | B2 | Prompt-injection persistence across turns |

---

## 4. Attacker model

We consider three attackers, in priority order:

- **A1 — Indirect prompt injection (primary).** Attacker controls content the LLM ingests:
  a web page Veronica browses, a document the File agent summarizes, a CVE/API response, a
  RAG-indexed file. Goal: steer the LLM into emitting a malicious tool call (exfil, scan a
  third party, run a shell payload).
- **A2 — Malicious/compromised local user (secondary).** The operator themselves typing
  hostile input. Lower priority for a single-user local tool, but relevant because the same
  text path feeds the LLM and the tool router.
- **A3 — Network attacker (out of scope unless exposed).** Only relevant if `app.py` is bound
  to a non-loopback interface. **Mitigation: don't do that.** No auth model is assumed.

Out of scope: physical access, supply-chain compromise of pinned dependencies, Ollama model
weights tampering.

---

## 5. Controls in place

### C1 — Tool allowlist (HackingTool fleet) — `ht_wrapper.py`
The 183-tool index is gated down to ~25 runnable IDs. Offensive categories (DDoS, phishing
payloads, C2, payload creators, RAT/remote-admin) are **never** reachable from the router.
Two tiers: `SAFE_TOOLS` (passive recon/OSINT, run freely) and `EXTENDED_TOOLS` (active
fuzz/scan, require an explicit `allow_extended=True`). Capability-based, default-deny. This is
the strongest control in the system.

### C2 — No arbitrary shell flags
`--command`, `--force`, `--privileged` are never constructed by the wrapper. The model cannot
request a free-form shell command through the sanctioned path.

### C3 — SSRF guard (non-security fetches) — `url_guard.py`
For news/research/document fetches: scheme allowlist (http/https only), blocked hostnames
(localhost, cloud-metadata names), private/reserved/loopback/link-local IP rejection, and a
DNS-resolution check that rejects if **any** resolved address is internal (rebinding-aware).
*Intentionally not applied to Ultron* — scanning internal hosts is its job.

### C4 — Circuit breaker + rate throttle — `core/llm.py`, API throttle
Fail-fast when Ollama is down; shared throttle on outbound API calls. Availability control,
also limits blast radius of a runaway agent loop.

### C5 — Config validator — `core/config_validator.py`
On boot, reports which keys/tools are present. Loud, never fatal. Reduces misconfiguration
(e.g. accidentally running with a tool backend the user didn't intend).

### C6 — Secrets handling — `.gitignore`
`.env`, `*.key`, `*.pem`, and all runtime JSON memory stores are git-ignored. No secrets are
constructed in source.

### C7 — Network egress isolation (recommended hardening, deployment-level)
C3 stops the *assistant's own* fetches from reaching internal hosts, but a hijacked tool command
(A1) could still exfiltrate via raw `curl`/`wget`/sockets. For any exposed or container
deployment, run the agent in a network segment whose **outbound traffic is allowlisted** to only
the endpoints it actually needs (Ollama, the authorized recon targets, required APIs) and block
arbitrary egress. Then, even if an injected command executes, it cannot phone home with stolen
data. This is the OS/network-layer complement to the app-layer SSRF guard (C3). Documented as a
recommendation — not enforced by the code, since the single-user local default assumes a trusted
host. (Concept adapted from Hermes Agent's egress-isolation guidance, MIT.)

---

## 6. Weaknesses (W1–W4 fixed; W5–W7 open)

> Documented deliberately — found, ranked, and (where closed) fixed in the open.

### W1 — Shell-metacharacter denylist + `bash -lc` (B4) — ✅ FIXED (Batch 1)
**Was:** `ht_wrapper._SHELL_META` denylist, then args handed to `bash -lc` in `ht_run.py` —
a known-loser pattern (no protection vs quotes, glob, or flag injection).
**Now:** `ht_run.py` uses no shell. Every backend (native/WSL/Docker) `shlex.split`s the
command into an **argv array** and execs it directly, so shell metacharacters can't chain
commands. The denylist is kept only as defense-in-depth at the gate.
**Residual:** per-tool *flag* injection (e.g. an arg reaching the tool as `--output x`) — a
deeper per-tool arg-shape allowlist is future work. Shell RCE is closed.

### W2 — `shell=True` / `os.system` sinks (B3) — ✅ FIXED (Batch 1)
**Was:** `terminator_agent.py` (`os.system(f"start {cmd}")`, `Popen(cmd, shell=True)`) and
`veronica_agent.py` (`Popen(command, shell=True)`) executed on LLM/user-influenced strings.
**Now:** no `shell=True`, no `os.system`. `launch_app` is allowlist-only (unknown apps
refused) and execs via an argv list; URIs/`.msc` go through `os.startfile`. `veronica.open_app`
uses argv + `os.startfile`. Command injection sinks removed; covered by adversarial tests.

### W3 — SSRF guard not redirect- or encoding-complete (B5) — ✅ FIXED (Batch 2)
**Was:** `url_guard` validated the *initial* URL only (a public host `302`→`169.254.169.254`
was followed), and int/octal/hex-encoded IPs (`http://2130706433/` = 127.0.0.1) bypassed the
literal-IP check.
**Now:** `_normalize_host()` decodes decimal/hex/octal hosts before the private-IP check, and
`safe_get()` re-validates **every redirect hop** (allow_redirects=False + per-hop check). The
file-agent URL path fetches via `safe_get` → temp file → MarkItDown, so the library can't
follow a redirect to an internal host. Covered by adversarial tests.
**Residual:** full TOCTOU rebind-pinning (connect to the exact resolved IP) not yet done.

### W4 — Dead "safety" path (B1) — ✅ FIXED (Batch 1)
**Was:** `core/safety.py` (substring denylist of "hack"/"exploit"/"attack") + `core/agent_loop.py`
were dead code not in the live flow; the denylist would have blocked legit security queries.
**Now:** both deleted, plus two leftover temp files (`tmpl6bfy_2y.py`, `tmppopv4oit.py`).

### W5 — No prompt-injection defense at B2 — MEDIUM
Content the LLM ingests (browsed pages, summarized docs, API responses, RAG chunks) is fed to
the model without isolation. A1 (indirect injection) is currently mitigated only by the C1
allowlist limiting *what* a hijacked model can do — not by preventing the hijack.
**Fix:** mark tool-ingested content as untrusted in the prompt; require explicit confirmation
for state-changing / outbound actions triggered off ingested content; never let ingested
content choose scan targets or recipients. **Exfil sub-vector** (a hijack trying to phone data
home) is additionally contained by **C7 network egress isolation** in exposed/Docker
deployments — even a successful injection can't reach a non-allowlisted endpoint.

### W6 — No authentication / authorization (B1, A3) — accepted (local-only)
The Flask app assumes a single trusted local user. There is no auth. **Accepted** for the
intended deployment; documented so it is never accidentally exposed.

### W7 — Scan-authorization is honor-system (B4, B5) — MEDIUM → partially addressed
Nothing technically *blocks* pointing recon/scan tools at an unauthorized target. README states
"authorized targets only."
**Partially addressed:** `_scope_check` now runs at every active entry point (nmap / full_recon /
full_pipeline / bug_bounty) — it flags third-party / shared-SaaS hosts and warns when the target
isn't covered by an optional `data/scope.json` allowlist (`[ULTRON][SCOPE] …`). Advisory and
non-blocking by design (single-user local tool).
**Remaining:** make it a hard gate (refuse active scans on out-of-scope targets) + an explicit
per-target authorization acknowledgment for extended-tier tools.

---

## 7. Residual risk summary

| Boundary | Top risk | Current control | Residual |
|----------|----------|-----------------|----------|
| B2→B4 | LLM-driven malicious tool run | C1 allowlist, C2, **W1 argv-exec** | Low (per-tool flag injection only) |
| B2→B3 | Command injection | **W2 argv + allowlist** | Low (sinks removed) |
| B5 | SSRF to metadata/internal | C3, **W3 redirect + encoding checks** | Low (TOCTOU pin pending) |
| B2 | Indirect prompt injection | C1 (blast-radius) + C7 egress isolation (exfil) | Med (W5 open) |
| B4/B5 | Unauthorized scan target | `_scope_check` advisory + `data/scope.json` | Med (W7 advisory, not a hard gate) |
| B6 | Key leakage | C6 | Low |

**Closed:** W1, W2, W3, W4 (commits in the `Batch 1`/`Batch 2` security passes).
**Still open:** W5 (prompt-injection isolation), W7 (scan-authorization enforcement); W6 accepted.

---

## 8. Assumptions

- Single local operator on a trusted machine; `app.py` bound to loopback.
- Ollama model weights and pinned dependencies are not adversarially controlled.
- The operator has legal authorization for any target passed to Ultron.

*Last reviewed: maintained alongside the codebase. Update when any boundary, control, or
weakness changes.*
