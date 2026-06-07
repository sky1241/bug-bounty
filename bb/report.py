"""Générateur de rapport de vulnérabilité — applique docs/REPORTING_PROTOCOL.md.

Principe non négociable (règle Sky) : aucun rapport n'est produit tant que la
**Phase 0 (validation anti-faux-positif)** n'est pas entièrement verte. Le générateur
LÈVE `ReportNotValidated` sinon. On vérifie aussi que la cible est in-scope.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .scope import Scope

CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"
_TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "report_template.md"


class ReportNotValidated(Exception):
    """Levée quand on tente de générer un rapport sans validation complète."""


def cvss_label(score) -> str:
    """Label qualitatif CVSS (bornes officielles FIRST, identiques v3.1/v4.0)."""
    if score is None:
        return "?"
    s = float(score)
    if s == 0:
        return "None"
    if s < 4:
        return "Low"
    if s < 7:
        return "Medium"
    if s < 9:
        return "High"
    return "Critical"


@dataclass
class Validation:
    """Les 3 passes de la Phase 0 + le contrôle légal. Tout doit être True."""

    repro: bool = False       # Passe 1 : reproduction à froid (≥2x, session propre)
    false_pos: bool = False   # Passe 2 : faux positifs écartés
    cross: bool = False       # Passe 3 : contrôle croisé (impact, CWE, CVSS, PII)
    legal: bool = False       # scope respecté, non-destructif, données masquées

    def complete(self) -> bool:
        return all(asdict(self).values())

    def missing(self) -> list[str]:
        return [k for k, v in asdict(self).items() if not v]


@dataclass
class Finding:
    title: str
    summary: str = ""
    asset_url: str = ""
    asset_param: str = ""
    cwe_id: str = ""          # "79" ou "CWE-79"
    cwe_name: str = ""
    severity_system: str = "CVSS v3.1"
    cvss_vector: str = ""
    cvss_score: float | None = None
    severity_justification: str = ""
    prerequisites: str = ""
    steps: list[str] = field(default_factory=list)
    raw_request: str = ""
    expected: str = ""
    actual: str = ""
    payload: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    references: str = ""


def render(finding: Finding, validation: Validation, scope: Scope | None = None,
           *, enforce: bool = True) -> str:
    """Rend le rapport Markdown. Refuse (enforce=True) si la Phase 0 est incomplète."""
    if enforce and not validation.complete():
        raise ReportNotValidated(
            "Phase 0 incomplète — étapes manquantes: " + ", ".join(validation.missing())
            + ". Voir docs/REPORTING_PROTOCOL.md")

    scope_status = "non vérifié (fournir --program)"
    if scope is not None and finding.asset_url:
        if scope.allows(finding.asset_url):
            scope_status = "✅ in-scope (vérifié par Scope.allows)"
        else:
            scope_status = "❌ HORS-SCOPE — NE PAS SOUMETTRE"

    cwe = finding.cwe_id.replace("CWE-", "").strip()
    steps_md = "\n".join(f"{i + 1}. {s}" for i, s in enumerate(finding.steps)) or "1. (à compléter)"
    mapping = {
        "TITLE": finding.title,
        "SUMMARY": finding.summary or "(à compléter)",
        "ASSET_URL": finding.asset_url,
        "ASSET_PARAM": finding.asset_param or "—",
        "SCOPE_STATUS": scope_status,
        "CWE_ID": f"CWE-{cwe}" if cwe else "(à compléter)",
        "CWE_URL": CWE_URL.format(cwe) if cwe else "",
        "CWE_NAME": finding.cwe_name or "",
        "SEV_SYSTEM": finding.severity_system,
        "CVSS_VECTOR": finding.cvss_vector or "(à compléter sur first.org/cvss/calculator)",
        "CVSS_SCORE": finding.cvss_score if finding.cvss_score is not None else "—",
        "CVSS_LABEL": cvss_label(finding.cvss_score),
        "SEVERITY_JUSTIFICATION": finding.severity_justification or "(à compléter, métrique ↔ PoC)",
        "PREREQUISITES": finding.prerequisites or "—",
        "STEPS": steps_md,
        "RAW_REQUEST": finding.raw_request or "(coller la requête HTTP brute)",
        "EXPECTED": finding.expected or "—",
        "ACTUAL": finding.actual or "—",
        "PAYLOAD": finding.payload or "(payload exact)",
        "EVIDENCE": finding.evidence or "(joindre vidéo/captures annotées)",
        "IMPACT": finding.impact or "(à compléter : scénario réaliste démontré)",
        "REMEDIATION": finding.remediation or "(optionnel)",
        "REFERENCES": finding.references or "(optionnel)",
        "V_REPRO": "x" if validation.repro else " ",
        "V_FALSEPOS": "x" if validation.false_pos else " ",
        "V_CROSS": "x" if validation.cross else " ",
        "V_SCOPE": "x" if validation.legal else " ",
    }
    out = _TEMPLATE.read_text()
    for key, val in mapping.items():
        out = out.replace("{{" + key + "}}", str(val))
    return out


def finding_from_dict(d: dict) -> Finding:
    fields = Finding.__dataclass_fields__
    return Finding(**{k: v for k, v in d.items() if k in fields})


def validation_from_dict(d: dict) -> Validation:
    return Validation(**{k: bool(d.get(k, False)) for k in ("repro", "false_pos", "cross", "legal")})
