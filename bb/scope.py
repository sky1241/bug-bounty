"""Scope guard — le cœur légal du projet.

Aucune cible n'est testée si elle n'est pas explicitement autorisée par le scope
d'un programme. Principes (par ordre) :

1. **Out-of-scope l'emporte toujours.**
2. **Conservateur en in-scope, inclusif en out-of-scope.** En cas de doute on
   REFUSE (in) ou on BLOQUE (out) — jamais l'inverse.
3. **Un wildcard ``*`` ne traverse pas les points** (un ``*`` = un label, jamais une
   chaîne arbitraire). ``*.example.com`` couvre les sous-domaines (a.example.com,
   a.b.example.com) mais **pas** l'apex ``example.com`` ni ``evilexample.com``.
4. **Aucune confiance dans les données de feed** : patterns trop larges (``*``,
   ``*.com``), injections regex (``a.com|evil.com``), parenthèses déséquilibrées,
   hosts avec backslash/espace/newline → rejetés.

Durci suite à un audit adversarial (29 fuites hors-scope corrigées).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlparse

# Hostname strict : labels alphanumériques + tirets, pas d'unicode/underscore/espace.
_HOSTNAME_RX = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)
_FORBIDDEN = " \t\n\r\\"  # jamais dans un host (anti-injection newline/backslash/espace)


def _as_ip(host: str):
    """Canonicalise une IP (dotted/hex/octal/decimal-int/IPv6) ou renvoie None."""
    h = host
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    if h.isdigit():
        try:
            return str(ipaddress.ip_address(int(h)))
        except (ValueError, ipaddress.AddressValueError):
            return None
    if h.startswith("0x"):
        try:
            return str(ipaddress.ip_address(int(h, 16)))
        except ValueError:
            return None
    if "." in h and re.fullmatch(r"[0-9a-fx.]+", h):
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except OSError:
            return None
    return None


def normalize_host(target: str) -> str:
    """Extrait un host canonique (host nu/URL/host:port) ou "" si invalide/dangereux."""
    target = (target or "").strip().lower()
    if not target:
        return ""
    if any(c in target for c in _FORBIDDEN):
        return ""  # newline/backslash/espace → rejet immédiat (anti-évasion)
    if "://" not in target:
        target = "//" + target
    try:
        host = (urlparse(target).hostname or "").rstrip(".")
    except ValueError:
        return ""
    if not host:
        return ""
    ip = _as_ip(host)
    if ip is not None:
        return ip
    return host if _HOSTNAME_RX.match(host) else ""


def _clean_pattern(pattern: str) -> str:
    """Retire schéma, path et port d'un pattern pour ne garder que le host."""
    p = re.sub(r"^[a-z][a-z0-9+.-]*://", "", (pattern or "").strip().lower())
    p = p.split("/", 1)[0]
    p = re.sub(r":[\d*]+$", "", p)   # retire port numérique ET port-wildcard ':*'
    return p


@lru_cache(maxsize=8192)
def _compile_pattern(pattern: str):
    """Compile un pattern de scope en regex ancrée, OU None si dangereux/invalide.

    Rejette : parenthèses déséquilibrées, métacaractères regex hors syntaxe YWH,
    ``*`` non isolé comme label, wildcard catch-all (``*``, ``*.tld`` à 1 label).
    ``*`` → ``[^.]+`` (un label) ; préfixe ``*.`` → ``(?:[^.]+\\.)+`` (multi-niveau).
    """
    p = _clean_pattern(pattern)
    if not p or p.count("(") != p.count(")"):
        return None
    if any(c in p for c in "[]{}\\"):
        return None
    structural = re.sub(r"\([^()]+\)", "x", p)  # groupes d'alternation neutralisés
    if "|" in structural:
        return None  # '|' hors parenthèses = injection
    if re.search(r"(?:^|\.)\*[a-z0-9]", structural):
        return None  # '*' collé en début de label ('*example.com') = sur-match dangereux
    if p.startswith("*."):
        suffix = re.sub(r"\([^()]+\)", "x", p[2:]).replace("*", "")
        if len([l for l in suffix.split(".") if l]) < 2:
            return None  # '*.com' / '*' → trop large
    elif structural.strip(".") in ("", "*"):
        return None

    prefix, body = "", p
    if p.startswith("*."):
        prefix, body = r"(?:[^.]+\.)+", p[2:]
    out = [prefix]
    for ch in body:
        if ch == ".":
            out.append(r"\.")
        elif ch == "*":
            out.append(r"[^.]+")
        elif ch in "()|-":
            out.append(ch)
        else:
            out.append(re.escape(ch))
    try:
        return re.compile("^(?:" + "".join(out) + r")\Z")
    except re.error:
        return None


def _pattern_matches(host: str, pattern: str) -> bool:
    pattern = (pattern or "").strip().lower()
    if not pattern:
        return False
    if not any(c in pattern for c in "*()|[]?+{}"):
        norm = normalize_host(pattern)          # host plat : égalité stricte
        return bool(norm) and norm == host
    rx = _compile_pattern(pattern)              # wildcard / alternation : regex ancrée
    return bool(rx and rx.fullmatch(host))


@dataclass
class Scope:
    """Périmètre autorisé d'un programme."""

    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    def allows(self, target: str) -> bool:
        host = normalize_host(target)
        if not host:
            return False
        if any(_pattern_matches(host, p) for p in self.out_of_scope):
            return False
        return any(_pattern_matches(host, p) for p in self.in_scope)

    def reason(self, target: str) -> str:
        host = normalize_host(target)
        if not host:
            return f"REFUSÉ: cible illisible/invalide ({target!r})"
        for p in self.out_of_scope:
            if _pattern_matches(host, p):
                return f"REFUSÉ: {host} matche out-of-scope {p!r}"
        for p in self.in_scope:
            if _pattern_matches(host, p):
                return f"AUTORISÉ: {host} matche in-scope {p!r}"
        return f"REFUSÉ: {host} ne matche aucune règle in-scope"
