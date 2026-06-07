"""Récupération et cache local des feeds de programmes (sans auth)."""
from __future__ import annotations

import json
from pathlib import Path

_RAW = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"

FEEDS = {
    "hackerone": f"{_RAW}/hackerone_data.json",
    "bugcrowd": f"{_RAW}/bugcrowd_data.json",
    "intigriti": f"{_RAW}/intigriti_data.json",
    "yeswehack": f"{_RAW}/yeswehack_data.json",
    "federacy": f"{_RAW}/federacy_data.json",
}
YWH_API = "https://api.yeswehack.com/programs"
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "programs"


def _fetch(url: str, timeout: int = 60):
    import requests  # import paresseux : pas requis pour `list` (lecture du cache)

    r = requests.get(url, timeout=timeout, headers={"User-Agent": "bb-aggregator/0.1"})
    r.raise_for_status()
    return r.json()


def _fetch_ywh_all() -> list:
    items, page = [], 1
    while page <= 50:
        d = _fetch(f"{YWH_API}?page={page}")
        batch = d.get("items", [])
        items += batch
        nb_pages = (d.get("pagination") or {}).get("nb_pages", page)
        if not batch or page >= nb_pages:
            break
        page += 1
    return items


def update(data_dir: Path = DATA_DIR) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    for plat, url in FEEDS.items():
        data = _fetch(url)
        (data_dir / f"{plat}.json").write_text(json.dumps(data))
        print(f"  {plat}: {len(data)} programmes")
    items = _fetch_ywh_all()
    (data_dir / "yeswehack_api.json").write_text(json.dumps(items))
    print(f"  yeswehack_api: {len(items)} items (country/bounty FR)")


def load(data_dir: Path = DATA_DIR):
    feeds = {}
    for plat in FEEDS:
        f = data_dir / f"{plat}.json"
        if f.exists():
            feeds[plat] = json.loads(f.read_text())
    ywh_api = []
    af = data_dir / "yeswehack_api.json"
    if af.exists():
        raw = json.loads(af.read_text())
        # Tolère les 2 formats: liste d'items déjà extraite, OU réponse brute {items,pagination}
        ywh_api = raw.get("items", []) if isinstance(raw, dict) else raw
    return feeds, ywh_api
