"""Validation croisée fleet — anti-hallucination par résultats indépendants.

Principe (idée de Sky) : faire tourner la MÊME tâche sur 2 nœuds INDÉPENDAMMENT,
puis comparer. Ce que les deux voient = **consensus** (haute confiance). Ce qu'un
seul voit = **delta** (flakiness, couverture partielle, ou hallucination → à revérifier).
Puis **inversion des rôles** : chaque nœud re-vérifie le delta de l'autre.

`delta()` est pur (testable sans réseau). L'orchestration SSH réutilise `bb/fleet.py`.
"""
from __future__ import annotations

import json
import shlex
import subprocess

from .fleet import Node, scope_payload
from .scope import Scope


def _items(report: dict, key: str) -> set:
    """Extrait l'ensemble comparable d'un rapport recon (hosts=dicts, urls=str)."""
    v = (report or {}).get(key) or []
    if v and isinstance(v[0], dict):
        return {x.get("host") for x in v if x.get("host")}
    return set(v)


def delta(a: dict, b: dict, key: str = "hosts") -> dict:
    """Compare deux rapports recon sur `key`. Retourne consensus + ce qui diverge.

    `agreement` = Jaccard (1.0 = accord total = confiance ; bas = divergence à creuser).
    """
    sa, sb = _items(a, key), _items(b, key)
    union = sa | sb
    return {
        "key": key,
        "consensus": sorted(sa & sb),   # vu par les DEUX → haute confiance
        "only_a": sorted(sa - sb),      # delta A → à revérifier
        "only_b": sorted(sb - sa),      # delta B → à revérifier
        "agreement": round(len(sa & sb) / len(union), 3) if union else 1.0,
        "verdict": _verdict(len(sa & sb), len(union)),
    }


def _verdict(inter: int, union: int) -> str:
    if union == 0:
        return "vide (rien trouvé des deux côtés)"
    ratio = inter / union
    if ratio >= 0.9:
        return "FIABLE (accord fort entre les 2 nœuds)"
    if ratio >= 0.6:
        return "À VÉRIFIER (divergence modérée — revoir le delta)"
    return "SUSPECT (forte divergence — possible flakiness/hallucination)"


def _ssh_recon(node: Node, domain: str, scope: Scope, extra: str = "", timeout: int = 1800) -> dict:
    """Exécute un recon sur un nœud et renvoie le rapport JSON (mode worker)."""
    payload = scope_payload(scope)
    remote = (f"cd {shlex.quote(node.repo)} && PYTHONPATH=. PATH=$HOME/.local/bin:$PATH "
              f"python3 -m bb recon {shlex.quote(domain)} --scope-file - --json {extra}")
    cmd = ["ssh", node.name, remote] if node.name != "local" else ["bash", "-lc", remote]
    try:
        out = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=timeout)
        return json.loads(out.stdout) if out.stdout.strip() else {}
    except (subprocess.SubprocessError, OSError, ValueError):
        return {}


def cross_verify(domain: str, scope: Scope, node_a: Node, node_b: Node, *,
                 key: str = "hosts", runner=_ssh_recon) -> dict:
    """Lance le MÊME recon sur 2 nœuds indépendants et calcule le delta (anti-hallucination)."""
    ra = runner(node_a, domain, scope)
    rb = runner(node_b, domain, scope)
    d = delta(ra, rb, key=key)
    d["nodes"] = [node_a.name, node_b.name]
    d["counts"] = {node_a.name: len(_items(ra, key)), node_b.name: len(_items(rb, key))}
    return d
