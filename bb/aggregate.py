"""Normalisation des feeds bug-bounty hétérogènes en objets Program uniformes.

Les 5 feeds de `bounty-targets-data` ont chacun un schéma différent (champ du nom
de l'asset, champ du type, champ de la prime). On parse de façon générique et
défensive, et on construit le Scope de chaque programme via le scope guard.
"""
from __future__ import annotations

import re

from .models import Program
from .scope import Scope, _compile_pattern, normalize_host

# Champs candidats pour l'identifiant et le type d'un asset, selon les plateformes :
#   hackerone -> asset_identifier / asset_type
#   bugcrowd  -> target / type
#   intigriti -> endpoint / type
#   federacy  -> target / type
#   yeswehack -> target / type
_ID_FIELDS = ("asset_identifier", "target", "endpoint", "uri")
_TYPE_FIELDS = ("asset_type", "type")


def categorize(typ: str, val: str) -> str:
    """Catégorise un asset à partir de son type et de sa valeur."""
    t = (typ or "").lower()
    v = (val or "").lower()
    if "*" in v or "wild" in t:
        return "web"
    if any(k in t for k in ("mobile", "android", "ios", "apk", "ipa", "app_id", "play", "apple", "testflight")):
        return "mobile"
    if "contract" in t or "smart" in t:
        return "web3"
    if "hardware" in t:
        return "hardware"
    if "source" in t or "executable" in t:
        return "source"
    if t in ("cidr", "ip_address", "ip"):
        return "network"
    if any(k in t for k in ("url", "web", "api", "website", "endpoint", "application")):
        return "web"
    if t in ("", "other") and "." in v and " " not in v:
        return "web"  # type inconnu mais la valeur ressemble à un host/URL
    return "other"


def _scope_items(targets) -> list[tuple[str, str]]:
    """Extrait [(identifiant, type)] d'une liste d'assets, peu importe la plateforme."""
    items = []
    for a in targets or []:
        if not isinstance(a, dict):
            continue
        val = next((a[f] for f in _ID_FIELDS if a.get(f)), None)
        typ = next((a[f] for f in _TYPE_FIELDS if a.get(f)), "")
        if val:
            items.append((str(val).strip(), str(typ).strip().lower()))
    return items


_OUT_HOST_RX = re.compile(r"\*?\.?[a-z0-9][a-z0-9.\-]*\.[a-z0-9\-]+")


def _in_patterns(items: list[tuple[str, str]]) -> list[str]:
    """Patterns IN-SCOPE (conservateur) : seuls les assets web, patterns validés.

    Un pattern riche (wildcard/alternation) n'est gardé que si `_compile_pattern`
    l'accepte (rejette catch-all, injections, etc.). Sinon on préfère rater la
    cible que sur-autoriser.
    """
    pats = set()
    for val, typ in items:
        if categorize(typ, val) != "web":
            continue
        v = (val or "").strip().lower()
        if any(c in v for c in "*()|"):
            if _compile_pattern(v) is not None:
                pats.add(v)
        else:
            h = normalize_host(v)
            if h:
                pats.add(h)
    return sorted(pats)


def _out_patterns(items: list[tuple[str, str]]) -> list[str]:
    """Patterns OUT-OF-SCOPE (inclusif) : on bloque large, type ignoré.

    On extrait tout host/wildcard d'une valeur même sale ('admin.x.com (do not
    test)', 'a.x.com|b.x.com'), et pour un wildcard '*.x' on ajoute l'apex 'x'
    (sur-bloquer plutôt que laisser fuir).
    """
    pats = set()
    for val, _typ in items:
        v = (val or "").strip().lower()
        for chunk in re.split(r"[\s,|]+", v):
            c = re.sub(r"^[a-z][a-z0-9+.-]*://", "", chunk)
            c = c.split("/")[0].split(":")[0].strip("()").strip(".")
            if not c or ".." in c:
                continue
            if _OUT_HOST_RX.fullmatch(c):
                pats.add(c)
                if c.startswith("*."):
                    pats.add(c[2:])  # apex inclus côté out-of-scope
    return sorted(pats)


def _num(x):
    try:
        return float(x) if x not in (None, "", False, True) else None
    except (TypeError, ValueError):
        return None


def parse_program(platform: str, raw: dict) -> Program | None:
    if not isinstance(raw, dict):
        return None
    name = raw.get("name") or raw.get("title") or raw.get("id") or "?"
    url = raw.get("url") or ""
    handle = str(raw.get("handle") or raw.get("id") or raw.get("company_handle") or "")

    targets = raw.get("targets") or {}
    in_items = _scope_items(targets.get("in_scope"))
    out_items = _scope_items(targets.get("out_of_scope"))
    scope = Scope(in_scope=_in_patterns(in_items), out_of_scope=_out_patterns(out_items))
    cats = frozenset(categorize(t, v) for v, t in in_items)

    min_b = _num(raw.get("min_bounty"))
    max_b = _num(raw.get("max_bounty")) or _num(raw.get("max_payout"))
    pays_cash = bool(raw.get("offers_bounties") or raw.get("offers_awards") or (max_b and max_b > 0))

    state = (raw.get("submission_state") or raw.get("status") or "").lower()
    is_open = True
    if state and state not in ("open", "running", "active", "live"):
        is_open = False
    if raw.get("disabled") is True:
        is_open = False
    if raw.get("public") is False:
        is_open = False

    managed = bool(raw.get("managed_program") or raw.get("managed_by_bugcrowd"))

    return Program(
        platform=platform, name=str(name), url=str(url), handle=handle,
        pays_cash=pays_cash, min_bounty=min_b, max_bounty=max_b,
        is_open=is_open, scope=scope, categories=cats, managed=managed,
    )


def aggregate(feeds: dict) -> list[Program]:
    progs: list[Program] = []
    for platform, raw_list in feeds.items():
        for raw in raw_list or []:
            p = parse_program(platform, raw)
            if p:
                progs.append(p)
    return progs


def _norm(s: str) -> str:
    return "".join(ch for ch in str(s).lower() if ch.isalnum())


def enrich_ywh(programs: list[Program], ywh_api_items: list) -> list[Program]:
    """Enrichit les programmes YesWeHack via l'API YWH : pays, nb de rapports, dernière maj.

    Jointure best-effort par nom/handle normalisé (l'API expose des champs absents
    du feed arkadiyt : country, reports_count, last_update_at).
    """
    by_key = {}
    for it in ywh_api_items or []:
        if not isinstance(it, dict):
            continue
        for key in (it.get("title"), it.get("slug")):
            if key:
                by_key[_norm(key)] = it
    for p in programs:
        if p.platform != "yeswehack":
            continue
        it = by_key.get(_norm(p.name)) or by_key.get(_norm(p.handle))
        if not it:
            continue
        if it.get("country"):
            p.country = it["country"]
        if it.get("reports_count") is not None:
            p.reports_count = it["reports_count"]
        if it.get("last_update_at"):
            p.last_update = str(it["last_update_at"])[:10]
    return programs


# Alias rétro-compatible
enrich_country = enrich_ywh


def starter(programs: list[Program], require_cash: bool = True) -> list[Program]:
    """Programmes débutant-friendly triés par `starter_score` (les + prometteurs d'abord)."""
    base = beginner(programs, require_cash=require_cash)
    return sorted(base, key=lambda p: (p.starter_score, p.max_bounty or 0), reverse=True)


def beginner(programs: list[Program], require_cash: bool = True) -> list[Program]:
    """Filtre 'débutant-friendly' : paye cash + ouvert + surface web + scope gateable."""
    out = []
    for p in programs:
        if require_cash and not p.pays_cash:
            continue
        if not p.is_open:
            continue
        if not p.web_surface:
            continue
        if not p.scope.in_scope:
            continue
        out.append(p)
    return out


def sort_programs(programs: list[Program], by: str = "bounty") -> list[Program]:
    if by == "surface":
        return sorted(programs, key=lambda p: (p.wildcard_count, p.in_scope_count), reverse=True)
    return sorted(programs, key=lambda p: (p.max_bounty or 0, p.wildcard_count), reverse=True)
