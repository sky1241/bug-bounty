"""Tests du générateur de rapport — surtout le verrou anti-faux-positif."""
import pytest

from bb.report import (Finding, ReportNotValidated, Validation, cvss_label,
                       render)
from bb.scope import Scope


def _finding():
    return Finding(
        title="Stored XSS in profile name leading to session theft",
        summary="Le champ nom stocke du JS exécuté au rendu du profil.",
        asset_url="https://app.example.com/profile",
        cwe_id="CWE-79", cwe_name="Improper Neutralization (XSS)",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", cvss_score=7.4,
        steps=["Aller sur /profile", "Injecter <script>...</script>", "Recharger"],
        payload="<script>fetch('//x')</script>", impact="Vol de session admin.",
    )


def test_refuse_si_validation_incomplete():
    with pytest.raises(ReportNotValidated):
        render(_finding(), Validation(repro=True))  # 3 cases manquantes


def test_genere_si_validation_complete():
    v = Validation(repro=True, false_pos=True, cross=True, legal=True)
    md = render(_finding(), v)
    assert "{{" not in md and "}}" not in md       # tous les placeholders remplis
    assert "Stored XSS" in md
    assert "CWE-79" in md and "cwe.mitre.org/data/definitions/79" in md
    assert "[x]" in md                              # cases de validation cochées


def test_scope_status_in_et_hors_scope():
    v = Validation(repro=True, false_pos=True, cross=True, legal=True)
    in_scope = Scope(in_scope=["*.example.com"])
    assert "in-scope" in render(_finding(), v, scope=in_scope)
    out = Scope(in_scope=["*.autre.com"])
    assert "HORS-SCOPE" in render(_finding(), v, scope=out)


def test_draft_contourne_le_verrou():
    md = render(_finding(), Validation(), enforce=False)  # brouillon autorisé
    assert "[ ]" in md                                    # cases non cochées visibles


def test_no_placeholder_injection():
    """Un champ contenant '{{...}}' (ex. un payload) ne doit PAS être ré-interprété."""
    v = Validation(repro=True, false_pos=True, cross=True, legal=True)
    f = Finding(title="T", summary="payload {{CVSS_SCORE}} et {{EVIDENCE}}",
                cvss_score=7.5, evidence="SECRET_INTERNE")
    md = render(f, v)
    assert "payload {{CVSS_SCORE}} et {{EVIDENCE}}" in md   # littéral, non substitué
    # evidence n'a pas fui dans la section Summary via l'injection
    summary_section = md.split("## Affected", 1)[0]
    assert "SECRET_INTERNE" not in summary_section


def test_cvss_label_bornes():
    assert cvss_label(0) == "None"
    assert cvss_label(3.9) == "Low"
    assert cvss_label(6.9) == "Medium"
    assert cvss_label(8.9) == "High"
    assert cvss_label(9.0) == "Critical"
