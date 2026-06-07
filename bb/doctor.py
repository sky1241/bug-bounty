"""Diagnostic « doctor » : vérifie que tout le nécessaire est installé pour scanner.

`requests` est requis (bloquant). Les outils ProjectDiscovery sont recommandés mais
non bloquants (le recon a un fallback Python OSINT).
"""
from __future__ import annotations

import importlib.util

from . import recon

REQUIRED_PY = ["requests"]
PD_TOOLS = ["subfinder", "httpx", "nuclei"]


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def check() -> dict:
    report = {"python_deps": {}, "pd_tools": {}, "ready": True, "warnings": []}
    for dep in REQUIRED_PY:
        ok = _has_module(dep)
        report["python_deps"][dep] = ok
        if not ok:
            report["ready"] = False
            report["warnings"].append(f"module Python '{dep}' manquant (pip install {dep})")
    for tool in PD_TOOLS:
        path = recon.pd_path(tool)
        report["pd_tools"][tool] = path or False
        if not path:
            report["warnings"].append(f"{tool} absent → fallback Python (recon dégradé mais fonctionnel)")
    return report
