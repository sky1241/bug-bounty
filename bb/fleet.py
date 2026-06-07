"""Distribution stratégique du recon sur la fleet.

sky-master (orchestrateur) découpe les domaines in-scope d'un programme en shards
et les confie aux nœuds workers (cousins Kali pc1/pc3 + local) qui exécutent le
recon EN PARALLÈLE. Chaque worker reçoit le SCOPE explicite (pas besoin du cache
feeds) → il reste in-scope. sky-master agrège et journalise.

Le `runner` (effet de bord SSH) est injectable : la logique de répartition est
testable sans réseau.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass

from .scope import Scope


def seed_domains(scope: Scope) -> list[str]:
    """Domaines-graines à passer au recon, dérivés des patterns in-scope.

    `*.example.com` → `example.com` (subfinder énumère ses sous-domaines) ;
    host plat → lui-même. Les patterns riches (alternations) sont ignorés ici.
    """
    seeds = set()
    for p in scope.in_scope:
        p = p.lower().strip()
        if p.startswith("*."):
            base = p[2:]
            if base and "*" not in base and "(" not in base:
                seeds.add(base)
        elif not any(c in p for c in "*()|"):
            seeds.add(p)
    return sorted(seeds)


def shard(items, n: int):
    """Découpe `items` en `n` shards équilibrés (round-robin)."""
    items = list(items)
    n = max(1, n)
    out = [items[i::n] for i in range(n)]
    return [s for s in out if s] or [[]]


@dataclass
class Node:
    name: str              # alias SSH ('pc1', 'pc3') ou 'local'
    repo: str = "~/bug-bounty"
    weight: int = 1        # machine plus rapide → poids plus élevé → plus de cibles


def plan(domains, nodes: list[Node]) -> dict[str, list[str]]:
    """Répartit les domaines entre nœuds, pondéré par `weight`."""
    slots = []
    for n in nodes:
        slots += [n.name] * max(1, n.weight)
    shards = shard(domains, len(slots))
    by_node: dict[str, list[str]] = {n.name: [] for n in nodes}
    for name, sh in zip(slots, shards):
        by_node[name].extend(sh)
    return {k: v for k, v in by_node.items() if v}


def distribute(domains, scope: Scope, nodes: list[Node], *, runner) -> list[dict]:
    """Exécute le recon réparti. `runner(node, domains, scope) -> dict` injectable."""
    assignment = plan(domains, nodes)
    name_to_node = {n.name: n for n in nodes}
    results = []
    for name, doms in assignment.items():
        results.append(runner(name_to_node[name], doms, scope))
    return results


def scope_payload(scope: Scope) -> str:
    """Sérialise un scope pour l'envoyer à un worker."""
    return json.dumps({"in_scope": scope.in_scope, "out_of_scope": scope.out_of_scope})


def ssh_runner(node: Node, domains, scope: Scope, *, timeout: int = 1800) -> dict:
    """Runner réel : exécute `bb recon` sur un nœud via SSH (scope passé en stdin).

    Le worker doit avoir le repo (`node.repo`) et, idéalement, les outils PD.
    Renvoie un dict {node, ok, domains, results|error}.
    """
    payload = scope_payload(scope)
    doms = " ".join(shlex.quote(d) for d in domains)
    remote = (f"cd {shlex.quote(node.repo)} && "
              f"PYTHONPATH=. python3 -m bb recon {doms} --scope-file - --json -")
    cmd = ["ssh", node.name, remote] if node.name != "local" else ["bash", "-lc", remote]
    try:
        out = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=timeout)
        data = json.loads(out.stdout) if out.stdout.strip() else {}
        return {"node": node.name, "ok": out.returncode == 0, "results": data}
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        return {"node": node.name, "ok": False, "error": type(e).__name__}
