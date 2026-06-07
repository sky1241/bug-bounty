"""Gestion des dossiers d'engagement — un dossier ISOLÉ par programme testé.

`engagements/<slug>/` contient le scope figé, les résultats de recon et les findings.
Local par défaut (gitignored) : peut contenir des données de cible.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .scope import Scope

ENGAGEMENTS = Path(__file__).resolve().parent.parent / "engagements"


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-") or "engagement"


def path_for(name: str) -> Path:
    return ENGAGEMENTS / slugify(name)


def exists(name: str) -> bool:
    return path_for(name).exists()


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def create(name: str, scope: Scope, *, base: Path = ENGAGEMENTS) -> Path:
    """Crée (idempotent) le dossier d'engagement et y fige le scope."""
    d = base / slugify(name)
    (d / "recon").mkdir(parents=True, exist_ok=True)
    (d / "findings").mkdir(parents=True, exist_ok=True)
    (d / "scope.json").write_text(
        json.dumps({"name": name, "in_scope": scope.in_scope,
                    "out_of_scope": scope.out_of_scope}, indent=2, ensure_ascii=False))
    readme = d / "README.md"
    if not readme.exists():
        readme.write_text(
            f"# Engagement : {name}\n\nCréé : {_now()}\n\n"
            "- `scope.json` — périmètre figé (in/out-of-scope)\n"
            "- `recon/` — résultats de recon (JSON)\n"
            "- `findings/` — bugs validés + rapports\n\n"
            "Procédure : recon → valider 3× (Phase 0) → rapport. Voir docs/REPORTING_PROTOCOL.md\n")
    return d


def load_scope(name: str, *, base: Path = ENGAGEMENTS) -> Scope | None:
    f = base / slugify(name) / "scope.json"
    if not f.exists():
        return None
    d = json.loads(f.read_text())
    return Scope(in_scope=d.get("in_scope", []), out_of_scope=d.get("out_of_scope", []))
