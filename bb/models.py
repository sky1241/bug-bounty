"""Modèle normalisé d'un programme de bug bounty (toutes plateformes confondues)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .scope import Scope


@dataclass
class Program:
    platform: str                       # hackerone / bugcrowd / intigriti / yeswehack / federacy
    name: str
    url: str
    handle: str = ""
    pays_cash: bool = False
    min_bounty: float | None = None
    max_bounty: float | None = None
    is_open: bool = True
    country: str | None = None
    scope: Scope = field(default_factory=Scope)
    categories: frozenset = frozenset()  # {'web','mobile','web3','hardware','source','network','other'}
    managed: bool = False                # géré par la plateforme (gros client, souvent + chassé)
    reports_count: int | None = None     # YWH : nb de rapports historiques (proxy de saturation)
    last_update: str | None = None       # YWH : date de dernière maj du programme (YYYY-MM-DD)

    @property
    def web_surface(self) -> bool:
        return "web" in self.categories

    @property
    def in_scope_count(self) -> int:
        return len(self.scope.in_scope)

    @property
    def wildcard_count(self) -> int:
        return sum(1 for p in self.scope.in_scope if "*" in p)

    @property
    def difficulty(self) -> str:
        # Heuristique grossière: une grande surface (wildcards) = plus d'angles
        # accessibles à un débutant en recon. Ce n'est PAS une garantie de facilité.
        return "facile" if self.wildcard_count > 0 else "moyen"

    @property
    def starter_score(self) -> float:
        """Heuristique « bon pour débuter » (PAS une mesure exacte de concurrence,
        cette donnée n'existe pas publiquement). Combine des proxies défendables :
        peu de rapports historiques (bugs faciles encore là), prime motivante mais
        pas méga (moins de pros), surface wildcard, pertinence FR.
        """
        s = 0.0
        mb = self.max_bounty or 0
        if 100 <= mb <= 5000:
            s += 3                       # sweet-spot : motivant sans attirer tous les pros
        elif 5000 < mb <= 20000:
            s += 1
        elif mb > 20000:
            s -= 2                       # méga-bounty = saturé
        if self.wildcard_count > 0:
            s += 1                       # grande surface = plus d'angles
        if self.country == "FR":
            s += 2                       # marché FR moins saturé que les géants US
        if self.platform == "hackerone" and self.managed:
            s -= 1                       # gros client géré = très chassé (H1 seulement)
        if self.reports_count is not None:  # signal fort, dispo sur YesWeHack
            if self.reports_count < 100:
                s += 3
            elif self.reports_count < 300:
                s += 2
            elif self.reports_count < 700:
                s += 1
            elif self.reports_count >= 1500:
                s -= 1
        return s

    @property
    def bounty_str(self) -> str:
        if self.max_bounty:
            lo = int(self.min_bounty) if self.min_bounty else 0
            return f"{lo}-{int(self.max_bounty)}"
        return "cash" if self.pays_cash else "—"
