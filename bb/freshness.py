"""Détection des NOUVELLES offres (fraîcheur) — diff vs le dernier état vu.

Au lieu de re-regarder toute la liste, on ne montre que ce qui a été AJOUTÉ depuis
le dernier passage. Snapshot local (gitignored) des programmes déjà vus.
"""
from __future__ import annotations

import json
from pathlib import Path

SNAPSHOT = Path(__file__).resolve().parent.parent / "data" / "programs" / ".seen.json"


def _key(p) -> str:
    return f"{p.platform}:{(p.handle or p.name).lower()}"


def new_programs(programs, *, snapshot: Path = SNAPSHOT):
    """Retourne (nouveaux_programmes, first_run). Met à jour le snapshot.

    first_run=True au tout premier passage (on initialise, rien n'est « nouveau »).
    """
    snapshot = Path(snapshot)
    first_run = not snapshot.exists()
    seen = set()
    if not first_run:
        try:
            seen = set(json.loads(snapshot.read_text()))
        except (ValueError, OSError):
            seen = set()
    current = {_key(p) for p in programs}
    new_keys = current - seen
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(json.dumps(sorted(current)))
    if first_run:
        return [], True
    return [p for p in programs if _key(p) in new_keys], False
