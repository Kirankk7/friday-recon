# ===== LOCAL JARVIS CONFIGURATION =====
# Privacy-first, offline, self-hosted

import os
from dotenv import load_dotenv
load_dotenv()

# OLLAMA LOCAL LLM CONFIG
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

# Available models (check with: ollama list):
# OLLAMA_MODEL = "gemma:2b"          # Lightweight, fast
# OLLAMA_MODEL = "mistral:7b"        # Balanced (recommended)
# OLLAMA_MODEL = "llama2:7b"         # General purpose
# OLLAMA_MODEL = "deepseek-r1:8b"    # Code & reasoning
# OLLAMA_MODEL = "neural-chat:7b"    # Conversational

# ── Phase 52 #3 — per-agent model routing ──
# ask_llm(agent=...) resolves its model here, falling back to OLLAMA_MODEL.
# Map an agent → a model you've pulled (`ollama list`). Unmapped agents and
# unpulled models degrade gracefully to OLLAMA_MODEL.
# Example once you pull a coder model:
#   AGENT_MODELS = {"ultron": "deepseek-coder:6.7b", "echo": "deepseek-coder:6.7b"}
AGENT_MODELS = {}

def model_for(agent: str | None) -> str:
    """Resolve an agent name to its configured model (or the default)."""
    return AGENT_MODELS.get(agent, OLLAMA_MODEL) if agent else OLLAMA_MODEL

# ── Phase 56 — AutoTune (context-adaptive sampling + EMA learning) ──
AUTOTUNE_ENABLED = os.getenv("AUTOTUNE_ENABLED", "1") not in ("0", "false", "False")

# ── Phase 57 — Critic pass (gated self-review of high-stakes, non-streaming answers) ──
# Adds one extra LLM round (critique + revise) to Ultron/Athena report synthesis.
# Off by default — it doubles latency on those long calls. Set to 1 to enable.
CRITIC_ENABLED = os.getenv("CRITIC_ENABLED", "0") not in ("0", "false", "False")

# WHISPER STT CONFIG (Phase 17)
WHISPER_MODEL   = "base"    # tiny/base/small/medium — base is good balance on RTX 4060
WHISPER_DEVICE  = "cuda"    # cuda or cpu
WHISPER_DTYPE   = "float16" # float16 (GPU) or int8 (CPU)

# STT BACKEND — Phase 17b
# "whisper" = faster-whisper (default, always works)
# "parakeet" = nvidia/parakeet-tdt-1.1b via NeMo (faster, requires: pip install nemo_toolkit[asr])
STT_BACKEND = "whisper"
PARAKEET_MODEL = "nvidia/parakeet-tdt-0.6b"   # 0.6b = ~2GB VRAM, fast. 1.1b = ~4GB, more accurate

# TTS BACKEND
# "edge" = edge-tts (cloud, Microsoft Azure, requires internet)
# "kokoro" = local Kokoro-82M neural TTS (offline, no internet needed)
TTS_BACKEND = "kokoro"

# EARCONS (Phase 51 #11) — short per-agent audio cue before each agent speaks
EARCONS_ENABLED = True

# BARGE-IN (Phase 51 #10) — interrupt JARVIS by speaking while it talks
# Monitors mic during TTS; sustained speech above the threshold stops playback
# and records your new command. Threshold sits ABOVE the TTS echo bleed.
BARGE_IN_ENABLED    = True
BARGE_RMS_THRESHOLD = 0.07   # raise if TTS echo false-triggers; lower if it won't interrupt
BARGE_SUSTAIN_CHUNKS = 2     # consecutive loud 0.2s chunks needed (~0.4s of speech)

# BROWSER (Veronica agent — Playwright)
# Auto-on: Playwright launches LAZILY on the first browser command (never at boot),
# so startup stays safe even if Chrome/Playwright misbehaves. No manual "enable browser"
# needed. Worker fails gracefully if Chrome can't launch. Set False only to hard-disable.
BROWSER_ENABLED = True

# VOICE LOOP — Phase 28
VOICE_LOOP_AUTO_START = False   # Set True to start autonomous voice pipeline on boot

# ── Phase 39 — Football-Data.org ──
# Free key: https://www.football-data.org/client/register
# Free tier: 10 req/min | competitions: PL, BL1, SA, PD, FL1, CL, EC + national teams
FOOTBALL_API_KEY = os.getenv("FOOTBALL_API_KEY", "")

# ── Phase 30a — NVD NIST API ──
# Free key: https://nvd.nist.gov/developers/request-an-api-key
# Rate limit: 50 req/30s with key, 5 req/30s without
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# ── Phase 30b — VirusTotal API ──
# Free key: https://virustotal.com/gui/join-us
# Free tier: 4 req/min, 500/day. File/URL/domain reputation.
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ── Phase 33 — GitHub API (Athena code/repo search) ──
# Free token: github.com/settings/tokens (classic, public_repo scope is enough).
# Without token: 60 req/hr + NO code search. With token: 5000/hr + code search.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ── Phase 53 — n8n automation (self-hosted) ──
# Run n8n locally: docker run -it --rm -p 5678:5678 -v n8n_data:/home/node/.n8n n8nio/n8n
# Each workflow with a Webhook trigger is reachable at {N8N_BASE_URL}/webhook/{path}.
# N8N_API_KEY (optional) enables listing workflows via the REST API.
N8N_BASE_URL = os.getenv("N8N_BASE_URL", "http://localhost:5678")
N8N_API_KEY  = os.getenv("N8N_API_KEY", "")

# ── Phase 36 — HackingTool fleet (180+ tools via Ultron, scoped allowlist) ──
# Backend for ht_run: "auto" (ht_env picks WSL>Docker on Windows), "docker"
# (isolation), "wsl", or "native". Docker Desktop or a WSL distro required on
# Windows; tools degrade gracefully (status=no_backend) when neither is present.
HT_BACKEND = os.getenv("HT_BACKEND", "auto")

# ── Phase 59 — local multimodal vision ──
# Ollama vision model for image understanding / screenshots. Pull one to enable:
#   ollama pull llava        (or llama3.2-vision, qwen2-vl, moondream)
# Features degrade gracefully (with install hint) when no vision model is present.
VISION_MODEL = os.getenv("VISION_MODEL", "llava")

# ── Phase 63 — Burp traffic ingestion (Community edition; no Pro/API key needed) ──
# Primary path is file export (ingest_burp <export.xml>). Optionally set this to the
# Burp MCP server's HTTP endpoint for a best-effort live pull. Empty = file-only.
BURP_MCP_URL = os.getenv("BURP_MCP_URL", "")

# ── Phase 61 — proactive engine (JARVIS reaches out: digest + alerts) ──
PROACTIVE_ENABLED     = os.getenv("PROACTIVE_ENABLED", "1") not in ("0", "false", "False")
PROACTIVE_DIGEST_HOUR = int(os.getenv("PROACTIVE_DIGEST_HOUR", "8"))   # morning brief after this hour
PROACTIVE_DEFENSE_MIN = int(os.getenv("PROACTIVE_DEFENSE_MIN", "0"))   # host re-scan interval (0=off)
PROACTIVE_CVE_MIN     = int(os.getenv("PROACTIVE_CVE_MIN", "180"))     # CVE watchlist check interval

# ── Phase 52 #8 — optional access token (auth-ready) ──
# JARVIS binds to 127.0.0.1 (localhost only), so this is OFF by default.
# Set JARVIS_TOKEN to require it on every request (header X-JARVIS-Token or
# ?token=…) — useful if you ever expose the app via a reverse proxy / 0.0.0.0.
JARVIS_TOKEN = os.getenv("JARVIS_TOKEN", "")

# NO CLOUD APIS
# - No OpenAI
# - No Gemini
# - No Claude
# - No Groq
# - No Together
# All inference runs locally on this machine
