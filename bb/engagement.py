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

# Checklist figée du protocole général (docs/METHODOLOGY.md) : on suit le MÊME
# protocole à chaque projet — garanti par le code, pas par la mémoire de l'opérateur.
_CHECKLIST = """# Checklist de test — {name}

Protocole général : `docs/METHODOLOGY.md`. Cocher au fur et à mesure. Tracer dans `bb journal`.

## Phase 0 — Cadrage (sky-master)
- [ ] Policy lue (scope in/out, rate-limit, exclusions, comptes de test)
- [ ] Scope figé (scope.json)
- [ ] Non-testable listé (DoS / social-eng / exfil de masse / sous-traitants)
- [ ] Système de sévérité noté (CVSS 3.1 par défaut / VRT P1-P5 Bugcrowd)

## Phase 1 — Recon (pc1 + pc3)
- [ ] Sous-domaines multi-sources (subfinder + crt.sh + hackertarget)
- [ ] Filtrage in-scope (Scope.allows) AVANT toute requête active
- [ ] Hôtes vivants (httpx ProjectDiscovery, pas l'homonyme Python)
- [ ] Erreurs de sources journalisées (pas de « 0 résultat » silencieux)

## Phase 2 — Mapping (pc1 + pc3)
- [ ] Points d'entrée catalogués (URLs, paramètres, headers, cookies, API, uploads)
- [ ] Rôles & frontières d'autorisation (anon / user / admin)
- [ ] Fonctions sensibles (paiement, reset, change email, export) + zones moins testées

## Phase 3 — Test WSTG (par catégorie — anti-omission)
- [ ] WSTG-CONF (headers, méthodes HTTP, backups, interfaces admin, buckets cloud)
- [ ] WSTG-ATHN (creds par défaut, lockout, recovery, MFA)
- [ ] WSTG-ATHZ (IDOR/BOLA, priv-esc, directory traversal)
- [ ] WSTG-SESS (cookies, CSRF, JWT, fixation)
- [ ] WSTG-INPV (XSS, SQLi, SSRF, injections)
- [ ] WSTG-ERRH / CRYP / BUSL / CLNT / APIT

## Phase 4 — Validation anti-faux-positif (3 passes — sky-master + pc2)
- [ ] Reproduction à froid >= 2x (session propre)
- [ ] FP classiques écartés (self-XSS / WAF / scanner brut / théorique / duplicate / hors-scope)
- [ ] Contrôle croisé (impact réel, CWE spécifique, CVSS cohérent, PII masquée)
- [ ] Re-validation indépendante par pc2 (double regard)

## Phase 5 — Rapport (pc2 = maître rapports)
- [ ] `bb report` (refuse si Phase 4 incomplète) + checklist `REPORTING_PROTOCOL.md`
"""


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
    scope_file = d / "scope.json"
    if not scope_file.exists():  # idempotent : ne pas écraser un scope déjà figé/édité
        scope_file.write_text(
            json.dumps({"name": name, "in_scope": scope.in_scope,
                        "out_of_scope": scope.out_of_scope}, indent=2, ensure_ascii=False))
    checklist = d / "CHECKLIST.md"
    if not checklist.exists():  # protocole figé, identique à chaque projet
        checklist.write_text(_CHECKLIST.format(name=name))
    readme = d / "README.md"
    if not readme.exists():
        readme.write_text(
            f"# Engagement : {name}\n\nCréé : {_now()}\n\n"
            "- `scope.json` — périmètre figé (in/out-of-scope)\n"
            "- `CHECKLIST.md` — protocole de test à suivre (6 phases, voir docs/METHODOLOGY.md)\n"
            "- `recon/` — résultats de recon (JSON)\n"
            "- `findings/` — bugs validés + rapports\n\n"
            "Protocole : 6 phases (Cadrage → Recon → Mapping → Test WSTG → Validation → Rapport).\n")
    return d


def load_scope(name: str, *, base: Path = ENGAGEMENTS) -> Scope | None:
    f = base / slugify(name) / "scope.json"
    if not f.exists():
        return None
    d = json.loads(f.read_text())
    return Scope(in_scope=d.get("in_scope", []), out_of_scope=d.get("out_of_scope", []))
