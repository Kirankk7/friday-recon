#!/usr/bin/env python3
"""
ht_env.py — Detect execution environment.

Prints JSON describing:
  - host OS (linux/macos/windows/unknown)
  - whether this Python is running inside WSL
  - on Windows: available WSL distros
  - whether Docker is available and responsive
  - preferred_backend: native | wsl | docker | fallback

Downstream (ht_run.py) uses preferred_backend to pick a runner.
"""

import json
import os
import platform
import shutil
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _detect_host() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s in ("linux", "windows"):
        return s
    return "unknown"


def _is_wsl() -> bool:
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="replace") as f:
            return "microsoft" in f.read().lower()
    except (FileNotFoundError, PermissionError, OSError):
        return False


# Internal WSL distros used by Docker Desktop / Rancher / Podman — not full Linux envs.
_SYSTEM_WSL_DISTROS = {
    "docker-desktop", "docker-desktop-data",
    "rancher-desktop", "rancher-desktop-data",
    "podman-machine-default",
}


def _wsl_distros() -> list[str]:
    if _detect_host() != "windows" or not _has("wsl"):
        return []
    try:
        r = subprocess.run(
            ["wsl", "-l", "-q"],
            capture_output=True, timeout=5,
        )
        if r.returncode != 0:
            return []
        raw = r.stdout
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        text = text.replace("\x00", "")
        distros = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return [d for d in distros if d.lower() not in _SYSTEM_WSL_DISTROS]
    except (subprocess.TimeoutExpired, OSError):
        return []


def _docker_ready() -> bool:
    if not _has("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def describe() -> dict:
    host = _detect_host()
    in_wsl = (host == "linux") and _is_wsl()
    wsl_distros = _wsl_distros()
    docker = _docker_ready()

    if host in ("linux", "macos"):
        backend = "native"
    elif host == "windows":
        if wsl_distros:
            backend = "wsl"
        elif docker:
            backend = "docker"
        else:
            backend = "fallback"
    else:
        backend = "fallback"

    return {
        "host": host,
        "arch": platform.machine(),
        "in_wsl": in_wsl,
        "wsl_distros": wsl_distros,
        "docker": docker,
        "preferred_backend": backend,
    }


if __name__ == "__main__":
    json.dump(describe(), sys.stdout, indent=2)
    sys.stdout.write("\n")
