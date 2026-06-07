"""Journal persistant du projet — le « dictionnaire » : historique append-only de
tout ce qu'on a testé (recon, bugs trouvés, faux positifs écartés, rapports, notes).

Format : un JSONL par projet (`journal/log.jsonl`). Append-only = on n'écrase
jamais l'historique. Local à CHAQUE repo de projet → les projets restent séparés.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "journal" / "log.jsonl"

# Types d'événements normalisés (le vocabulaire du dictionnaire).
TYPES = ("recon", "finding", "false_positive", "report", "note")


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def record(event_type: str, target: str = "", *, path: Path = DEFAULT_PATH, **data) -> dict:
    """Ajoute un événement daté au journal. Retourne l'entrée écrite."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": _now(), "type": event_type, "target": target, **data}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def load(path: Path = DEFAULT_PATH) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            pass  # ligne corrompue ignorée, le reste de l'historique reste lisible
    return out


def search(query: str = "", event_type: str | None = None, *, path: Path = DEFAULT_PATH) -> list[dict]:
    q = query.lower()
    res = []
    for e in load(path):
        if event_type and e.get("type") != event_type:
            continue
        if q and q not in json.dumps(e, ensure_ascii=False).lower():
            continue
        res.append(e)
    return res


def summary(path: Path = DEFAULT_PATH) -> dict:
    events = load(path)
    by_type: dict[str, int] = {}
    targets = set()
    for e in events:
        by_type[e.get("type", "?")] = by_type.get(e.get("type", "?"), 0) + 1
        if e.get("target"):
            targets.add(e["target"])
    return {"events": len(events), "by_type": by_type, "targets": sorted(targets)}
