# Protocole de test général (standardisé, distribué, anti-faux-positif)

> **Invariant** : on exécute **les mêmes 6 phases, dans le même ordre, à chaque
> projet**, peu importe le type de bug ou d'audit. L'exécution identique est garantie
> par le **code et les checklists**, pas par la mémoire de l'opérateur.

Sources métier (vérifiées) : OWASP **WSTG** (les 12 catégories de test), OWASP **ASVS**
(profondeur), **PTES** (7 phases), **NIST SP 800-115**, méthodologies de hunters
(Jason Haddix TBHM). Enveloppe process = PTES/NIST ; contenu du « quoi tester » = WSTG.

## Deux ennemis, deux garde-fous
- **Faux positif** → *« detection ≠ exploitation »*. Un payload qui apparaît dans une
  réponse ne prouve rien. → **Phase 4** (validation 3 passes, déjà câblée dans `bb/report.py`).
- **Bug silencieux** → deux formes : l'**omission** (catégorie non testée) et le
  **silence d'erreur** (une étape échoue sans le dire). → **WSTG = check-list de largeur**
  (anti-omission) + **règle : chaque étape vérifie son résultat et remonte ses erreurs**.

---

## Les 6 phases (répartition fleet)

| Phase | Quoi | Nœud(s) | Outil/commande |
|------|------|---------|----------------|
| **0 — Cadrage** | Figer scope, règles, exclusions, rate-limit, système de sévérité | **sky-master** | `bb scan --go` (fige le scope dans l'engagement) |
| **1 — Recon** | Sous-domaines, hôtes vivants, ports, technos, métafichiers | **pc1 + pc3** (parallèle) | `bb fleet --nodes pc1,pc3,local` |
| **2 — Mapping** | Points d'entrée, paramètres, rôles, fonctions sensibles, surface | **pc1 + pc3** | URLs Wayback + crawl (katana, roadmap) |
| **3 — Test WSTG** | Passer chaque endpoint contre les 12 catégories WSTG | **pc1 + pc3** (par catégorie) | nuclei ciblé + tests manuels par classe |
| **4 — Validation** | 3 passes anti-faux-positif (gatekeeper) | **sky-master + pc2** (croisé) | Phase 0 de `REPORTING_PROTOCOL.md` |
| **5 — Rapport** | Livrable standardisé (CVSS/CWE/PoC/impact) | **pc2** (maître rapports) | `bb report` |

> Règle de traçabilité : **une phase non journalisée = phase non faite** (`bb journal`).

---

## Phase 0 — Cadrage (légalité d'abord)
- Lire **toute** la policy : scope in/out, types autorisés, rate-limit, comptes de test, exclusions (P5/known-issues).
- Charger et **figer** le scope (`engagements/<slug>/scope.json`) — c'est CE fichier qui part à chaque worker (`--scope-file`).
- Lister le **NON-testable** (DoS, social-eng, exfil de masse, sous-traitants) — on n'y touche jamais.
- Noter le système de sévérité : **CVSS 3.1** (défaut, H1/YWH) ou **VRT P1–P5** (Bugcrowd).

## Phase 1 — Recon
- Sous-domaines via **sources multiples** (subfinder + crt.sh + hackertarget) — jamais une seule (couverture + résilience).
- Filtrer **in-scope (`Scope.allows`) avant toute requête active**, sur chaque nœud.
- Probe des hôtes vivants (httpx **PD**, pas l'homonyme Python) ; ports + fingerprint techno.
- **Anti-silence** : une source en échec (ex. crt.sh 502) est **journalisée**, jamais traitée comme « 0 résultat ».

## Phase 2 — Mapping
- Cataloguer points d'entrée : URLs, paramètres GET/POST, headers, cookies, endpoints API, uploads (WSTG-INFO-06).
- Cartographier les **rôles** et frontières d'autorisation (anon / user / admin) — base des tests AUTHZ.
- Repérer les **fonctions sensibles** (paiement, reset password, change email, export) et les **zones moins testées** (sous-domaines oubliés, API non documentées, beta) — meilleur ratio prime/effort.

## Phase 3 — Test : les 12 catégories WSTG (check-list de couverture)
On passe chaque endpoint mappé contre **chaque catégorie pertinente**. Aucune omission.

| Code | Catégorie | Exemples |
|------|-----------|----------|
| WSTG-INFO | Information Gathering | recon, fingerprint, métafichiers (Phases 1-2) |
| WSTG-CONF | Configuration & Deployment | headers, méthodes HTTP, backups, admin, buckets cloud |
| WSTG-IDNT | Identity Management | rôles, enrôlement, énumération d'usernames |
| WSTG-ATHN | Authentication | creds par défaut, lockout, bypass, recovery, MFA |
| WSTG-ATHZ | **Authorization** | directory traversal, **IDOR/BOLA**, priv-esc, OAuth |
| WSTG-SESS | Session Management | cookies, fixation, **CSRF**, logout, JWT |
| WSTG-INPV | **Input Validation** | **XSS**, **SQLi**, injections, **SSRF**, template injection |
| WSTG-ERRH | Error Handling | messages d'erreur, stack traces |
| WSTG-CRYP | Weak Cryptography | TLS faible, padding oracle, données non chiffrées |
| WSTG-BUSL | Business Logic | contournement de workflow, intégrité |
| WSTG-CLNT | Client-side | DOM XSS, postMessage, CORS, clickjacking |
| WSTG-APIT | API Testing | BOLA, mass assignment, rate-limit |

### Checklists par classe (les plus rentables débutant)
- **IDOR / BOLA** (WSTG-ATHZ-04 / API) : ≥ **2 comptes**, accéder à l'objet de l'autre (ID/UUID/slug). Confirmer = lire/modifier des données d'autrui. FP = c'est ta propre donnée.
- **Broken Access Control** (WSTG-ATHZ-02) : forced browsing, accès vertical (admin) / horizontal (pair). Confirmer = fonction/donnée hors de ton rôle.
- **XSS** (WSTG-INPV-01/02) : injection exécutée par non-encodage contextuel. Confirmer = **exécution** (vol de session / action), pas un `alert(1)` isolé. FP = payload bloqué par WAF / reflété sans exécution.
- **SQLi** (WSTG-INPV-05) : in-band/union, boolean-blind, time-based, error-based. Confirmer = extraction/altération démontrée (non destructive).
- **SSRF** (WSTG-INPV-19) : requête serveur vers URL contrôlée (interne, metadata cloud, file://). Détection souvent **out-of-band** (collaborator).
- **Subdomain takeover** : CNAME *dangling* + signature de service non revendiqué. Confirmer = revendication possible (sans héberger de contenu malveillant).

## Phase 4 — Validation anti-faux-positif (gatekeeper) — *« detection ≠ exploitation »*
**Aucun finding ne passe sans les 3 passes** (déjà câblées : `bb/report.py` lève `ReportNotValidated`) :
1. **Reproduction à froid** ≥ 2× (session/navigateur propre).
2. **Élimination des FP classiques** : self-XSS, WAF non bypassé, sortie scanner brute, impact théorique, duplicate, **hors-scope**.
3. **Contrôle croisé** : impact réel démontré, CWE spécifique, CVSS cohérent, PII masquée. Sur la fleet : **pc2 (rapporteur) re-valide** indépendamment ce que pc1/pc3 ont trouvé (double regard).

## Phase 5 — Rapport
Ossature canonique fixe (voir [REPORTING_PROTOCOL.md](REPORTING_PROTOCOL.md)) : Title → Summary →
Asset/Scope → CWE → Severity → Steps → PoC → Impact → Remediation → References. Généré par `bb report` sur **pc2**.

---

## Déterminisme & anti-bug-silencieux (exigences Sky, dans le CODE)
- **Standardisation par le code** : `bb scan --go` crée l'engagement **avec une checklist
  figée** (`CHECKLIST.md`) — on suit le même protocole à chaque projet, sans compter sur la mémoire.
- **Remontée d'erreurs obligatoire** : chaque source/étape qui échoue est journalisée
  (jamais « 0 résultat » silencieux). Vérifié par `forge --mutate` (mutation testing).
- **Idempotence / anti-doublon** : `bb scan` alerte si la cible a déjà un engagement / des recon au journal.
- **Validation par exit code, pas par texte** (CI) ; tests rejoués **sur pc1/pc3** à chaque CI.

## Distribution — règles
- **Sharding** : Phase 1-2-3 réparties par **asset/sous-domaine** sur pc1/pc3 (round-robin pondéré, `bb/fleet.py`).
- **Anti-doublon** : un host n'est testé qu'une fois (dédup à l'agrégation sky-master).
- **Rôles fixes** : sky-master orchestre + agrège ; pc1/pc3 recon+test ; **pc2 valide + rédige**.
