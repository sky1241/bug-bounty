"""Diagnostic « doctor » : vérifie que tout le nécessaire est installé pour scanner.

`requests` est requis (bloquant). Les outils ProjectDiscovery sont recommandés mais
non bloquants (le recon a un fallback Python OSINT).
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess

from . import recon

REQUIRED_PY = ["requests"]
CORE_PD = ["subfinder", "httpx", "nuclei"]          # critiques (fallback Python sinon)
PD_TOOLS = CORE_PD + ["dnsx", "katana", "naabu"]    # détectés via pd_path (-version)
EXTRA_TOOLS = ["gau", "ffuf"]                        # détectés par présence (flag version variable)


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _present(name: str) -> bool:
    p = os.path.expanduser(f"~/.local/bin/{name}")
    return (os.path.isfile(p) and os.access(p, os.X_OK)) or bool(shutil.which(name))


def _tool_version(path: str) -> str:
    try:
        out = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10)
        m = re.search(r"v?\d+\.\d+\.\d+", out.stdout + out.stderr)
        return m.group(0) if m else "?"
    except (subprocess.SubprocessError, OSError):
        return "?"


def check() -> dict:
    report = {"python_deps": {}, "pd_tools": {}, "versions": {}, "ready": True, "warnings": []}
    for dep in REQUIRED_PY:
        ok = _has_module(dep)
        report["python_deps"][dep] = ok
        if not ok:
            report["ready"] = False
            report["warnings"].append(f"module Python '{dep}' manquant (pip install {dep})")
    for tool in PD_TOOLS:
        path = recon.pd_path(tool)
        report["pd_tools"][tool] = path or False
        report["versions"][tool] = _tool_version(path) if path else None
        if not path and tool in CORE_PD:
            report["warnings"].append(f"{tool} absent → fallback Python (recon dégradé mais fonctionnel)")
        elif not path:
            report["warnings"].append(f"{tool} absent → recon réduit (scripts/install_tools.sh)")
    report["extra_tools"] = {t: _present(t) for t in EXTRA_TOOLS}
    for t, ok in report["extra_tools"].items():
        if not ok:
            report["warnings"].append(f"{t} absent (recommandé, scripts/install_tools.sh)")
    return report
