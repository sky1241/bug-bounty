<!--
  RAPPORT DE VULNÉRABILITÉ — gabarit standard (voir docs/REPORTING_PROTOCOL.md)
  Les marqueurs entre doubles accolades sont remplis par `python -m bb report`.
  ⛔ Ne soumettre QUE si la Phase 0 (validation anti-faux-positif) est verte.
-->

# {{TITLE}}
<!-- Formule: [type de vuln] in [endpoint précis] leading to [impact concret] -->

## Summary
{{SUMMARY}}
<!-- 2-3 phrases: quoi, où, pourquoi ça compte. Lisible par un non-expert. -->

## Affected Asset / Scope
- **Cible** : {{ASSET_URL}}
- **Paramètre / composant** : {{ASSET_PARAM}}
- **In-scope** : {{SCOPE_STATUS}}  <!-- vérifié via bb/scope.py -->

## Weakness
- **CWE** : [{{CWE_ID}}]({{CWE_URL}}) — {{CWE_NAME}}

## Severity
- **Système** : {{SEV_SYSTEM}}  <!-- CVSS (H1/YWH) ou VRT (Bugcrowd) -->
- **Vecteur** : `{{CVSS_VECTOR}}`
- **Score** : {{CVSS_SCORE}} ({{CVSS_LABEL}})
- **Justification** (métrique ↔ PoC) :
{{SEVERITY_JUSTIFICATION}}

## Steps to Reproduce
**Prérequis** : {{PREREQUISITES}}

{{STEPS}}
<!-- étapes numérotées, une action par ligne -->

**Requête HTTP (brute, copiable)** :
```http
{{RAW_REQUEST}}
```

- **Expected behavior** : {{EXPECTED}}
- **Actual behavior** : {{ACTUAL}}

## Proof of Concept & Evidence
**Payload** :
```
{{PAYLOAD}}
```
{{EVIDENCE}}
<!-- vidéo PoC de préférence, screenshots annotés au minimum, en fichiers attachés -->

## Impact
{{IMPACT}}
<!-- scénario d'attaque réaliste: attaquant, prérequis, gain, blast radius. Démontré. -->

## Remediation (optionnel)
{{REMEDIATION}}

## References (optionnel)
{{REFERENCES}}

<!--
  ── VALIDATION INTERNE (à retirer avant soumission) ──────────────────────────
  Phase 0:
    [{{V_REPRO}}] Passe 1 — reproduction à froid (≥2x, session propre)
    [{{V_FALSEPOS}}] Passe 2 — faux positifs écartés (self-XSS / WAF / scanner / théorique / dup / scope)
    [{{V_CROSS}}] Passe 3 — contrôle croisé (impact réel, CWE spécifique, CVSS cohérent, PII masquée)
  Légal:
    [{{V_SCOPE}}] scope respecté · non-destructif · données masquées · pas de divulgation
-->
