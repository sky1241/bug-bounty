# Protocole de rapport — à suivre À L'IDENTIQUE pour chaque bug

> Un bug est un bug. Ce qui fait la différence entre une prime et un rejet, c'est la
> **rigueur de validation** et la **présentation**. Ce protocole est non négociable :
> on le suit point par point, à chaque fois, peu importe la vuln. La checklist en fin
> de document EST le contrôle — aucun rapport n'est soumis sans l'avoir cochée en entier.

Sources officielles (vérifiées le 2026-06-07) : HackerOne *Quality Reports*, Bugcrowd
*Reporting a Bug*, YesWeHack *write-effective-reports*, FIRST.org *CVSS v4.0*, OWASP
*Risk Rating*, MITRE *CWE*.

---

## ⛔ Phase 0 — VALIDATION ANTI-FAUX-POSITIF (avant toute rédaction)

**On ne rédige RIEN tant que les 3 passes ne sont pas vertes.** Présenter un faux
positif détruit la réputation (HackerOne : `N/A` = **−5** de réputation, `spam` = −10).
On préfère jeter un bug douteux que soumettre un faux positif.

### Passe 1 — Reproduction à froid (indépendante)
- [ ] Repartir de **zéro** : nouvelle session privée / navigateur propre / nouveau compte.
- [ ] Suivre **ses propres** *steps to reproduce* à la lettre, sans raccourci mental.
- [ ] La vuln se reproduit **de façon déterministe** (≥ 2 fois d'affilée).
- ❌ Si non reproductible de façon fiable → **pas de rapport**.

### Passe 2 — Élimination des faux positifs classiques
Cocher que ce n'est **AUCUN** de ces pièges (causes de rejet documentées) :
- [ ] Ce n'est **pas** du **self-XSS** (nécessite que la victime colle elle-même le payload).
- [ ] Ce n'est **pas** un payload **bloqué par WAF** présenté comme XSS sans preuve de bypass.
- [ ] Ce n'est **pas** de la **sortie de scanner brute** non validée manuellement.
- [ ] L'impact est **démontré**, pas théorique (pas un `alert(1)` isolé, pas un header manquant sans conséquence).
- [ ] Ce n'est probablement **pas un duplicate** évident (recherche faite sur la cible).
- [ ] La cible est **strictement in-scope** → vérifiée par `bb/scope.py` (`Scope.allows`).

### Passe 3 — Contrôle croisé final (le 3ᵉ regard)
- [ ] Re-vérifier l'**impact réel** : quel actif business est touché, quel gain attaquant concret.
- [ ] **CWE** choisi = le plus **spécifique** qui colle (pas un parent vague).
- [ ] **CVSS** recalculé sur le calculateur officiel FIRST, vecteur cohérent avec le PoC métrique par métrique.
- [ ] Les preuves ne contiennent **aucune donnée sensible réelle** non masquée (PII, mots de passe, cartes).

> 🔁 **Règle Sky** : ce contrôle 3-passes est effectué **à chaque bug, sans exception**.
> Le générateur `bb/report.py` refusera de produire un rapport tant que ces cases ne sont
> pas validées.

---

## 🧱 L'ossature canonique du rapport (ordre fixe)

Les 3 plateformes décrivent la **même** structure sous des noms différents. On utilise
toujours cet ordre :

| # | Section | Règle |
|---|---------|-------|
| 1 | **Title** | Formule Bugcrowd : `[type de vuln] in [endpoint précis] allows/leading to [impact concret]`. Ex officiel H1 : *« Stored XSS in user profile field allows script execution on profile view »*. Jamais *« There's an XSS »*. |
| 2 | **Summary** | 2-3 phrases : quoi, où, pourquoi ça compte. Lisible par un non-expert (clarté > jargon, règle YWH). |
| 3 | **Asset / Scope** | L'actif exact affecté (URL, paramètre). Confirmer qu'il est in-scope. |
| 4 | **Weakness (CWE)** | ID CWE **le plus spécifique** + nom + lien MITRE. Ex : CWE-79 (XSS), CWE-89 (SQLi), CWE-639 (IDOR). Ne pas confondre avec CVE. |
| 5 | **Severity** | Vecteur **complet**, jamais un score nu (voir section sévérité). |
| 6 | **Steps to Reproduce** | Étapes **numérotées**, une action par étape. Prérequis explicites (URL, paramètre, rôle/compte). Requête HTTP **brute en texte copiable**. *Expected vs Actual*. |
| 7 | **Proof of Concept + Evidence** | Payload exact + preuve visuelle (**vidéo** de préférence, screenshots au minimum) en **fichiers attachés** (pas de liens externes). Captures **annotées**. |
| 8 | **Impact** | Scénario d'attaque réaliste (type d'attaquant, prérequis, gain, *blast radius*). **Démontré**, relié au PoC (Bugcrowd : *Demonstrated Impact*). |
| 9 | **Remediation** | Optionnel mais apprécié (gain de temps pour l'équipe). |
| 10 | **References** | CWE, OWASP WSTG, liens utiles. Optionnel. |

---

## 🎯 Sévérité — selon la plateforme (ne pas se tromper de système)

- **HackerOne / YesWeHack → CVSS.** Coller le **vecteur complet** + score + label qualitatif.
  - Calculateur officiel : `first.org/cvss/calculator/4.0` (ou `/3.1`).
  - Par défaut **CVSS v3.1**, sauf si le programme/VRT demande **v4.0** — préciser la version.
  - Bornes (identiques v3.1/v4.0) : None 0.0 · Low 0.1-3.9 · Medium 4.0-6.9 · High 7.0-8.9 · Critical 9.0-10.0.
  - Ne **jamais** mélanger v3.1/v4.0 (pas de `S:` en v4.0 ; pas de `AT:` en v3.1).
- **Bugcrowd → VRT P1-P5** (pas CVSS). P1 = Critical (RCE / priv-esc / vol financier), P2 = High… Citer la catégorie VRT.
- **Règle d'or** : justifier chaque métrique non-défaut par **une ligne reliée à une étape du PoC**
  (« C:H car l'étape 4 dump toute la table users »). Ne **jamais** gonfler « au cas où » → sanctionné.

---

## ⚖️ Règles légales & éthiques (non négociables)

- [ ] **Scope only** : ne jamais tester/rapporter un actif non listé (passe par `bb/scope.py`).
- [ ] **Non-destructif** : pas de DoS, pas d'exfiltration de données réelles en masse, pas de social engineering.
- [ ] **Preuve de bonne foi** : garder une trace des règles du programme acceptées.
- [ ] **Divulgation coordonnée** : ne rien divulguer publiquement (ni l'existence d'un programme privé) sans accord.

---

## ✅ CHECKLIST FINALE (le contrôle, identique à chaque fois)

**Validation** (Phase 0)
- [ ] Passe 1 reproduction à froid OK
- [ ] Passe 2 faux positifs écartés
- [ ] Passe 3 contrôle croisé OK

**Contenu**
- [ ] Title à la formule `[type] in [endpoint] → [impact]`
- [ ] Summary 2-3 phrases claires
- [ ] Asset in-scope vérifié par `Scope.allows`
- [ ] CWE le plus spécifique + lien MITRE
- [ ] Sévérité : vecteur CVSS complet (H1/YWH) **ou** VRT P1-P5 (Bugcrowd)
- [ ] Steps numérotés + requête HTTP brute copiable + Expected/Actual
- [ ] PoC : payload exact + preuve visuelle attachée (vidéo/screenshots annotés)
- [ ] Impact démontré + scénario réaliste relié au PoC
- [ ] (Remediation + References si pertinent)

**Légal**
- [ ] Scope respecté · non-destructif · données sensibles masquées · pas de divulgation

> Tant qu'une seule case n'est pas cochée, le rapport **n'est pas prêt**.
