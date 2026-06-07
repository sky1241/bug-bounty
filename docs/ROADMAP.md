# Roadmap — issue d'un deep audit (gaps vs méthodologie 2025)

Un audit multi-agents a comparé le repo à un pipeline bug bounty pro. Voici ce qui
est **fait** et ce qui **reste**, priorisé effort/impact. Les bugs de code signalés
par l'audit ont été **vérifiés** (fact-check).

## ✅ Déjà intégré
- `bb doctor`, `bb scan --go`, engagements (dossier isolé) — onboarding clé en main.
- **nuclei ciblé** (`-tags exposure,misconfig,takeover,default-login,cve -severity ... -rate-limit`)
  au lieu des ~9000 templates nus (bug confirmé corrigé).
- **httpx enrichi** (`-tech-detect -favicon -cdn -ip -cname`) au lieu de status/title/server seuls.
- **URLs historiques Wayback** (CDX, pur Python) — multiplicateur de surface, re-filtré par scope.
- Mutation testing (Forge) du scope guard : score 86%.

## 🔜 P1 — quick wins restants (effort faible / impact élevé)
- **Subdomain takeover en fallback Python** : résoudre le CNAME (dnspython) + fingerprints
  `can-i-take-over-xyz` (le `cname` est déjà collecté par httpx). Le bug le plus rentable débutant.
- **dnsx** (résolution + filtrage wildcard) avant le probe : évite les faux hosts vivants.
  Même famille PD → ajouter à `install_tools.sh` + `pd_path`.
- **Rate-limiting du fallback Python** (`_probe_requests` / `basic_checks`) : pacing + politesse
  (anti-ban) — fait pour nuclei/httpx, pas encore pour le chemin pur Python.
- **CVSS calculé** depuis le vecteur via la lib `cvss` (au lieu d'un float saisi à la main).

## 🔭 P2 — moyen effort
- **Dedup au recon** : relire le journal/un registre avant de re-scanner (anti « 15× la même chose »).
  Persister les hosts/findings dans un store (`bb/store.py`), diff entre runs.
- **JS crawling** (katana) + secrets (regex gitleaks ou `nuclei -t http/exposures/tokens/`).
- **Capture auto de la preuve HTTP** (requête/réponse `.http` rejouable) dans `findings/`.
- **Vérif machine de reproductibilité** : rejouer la requête ≥2× automatiquement (anti-faux-positif).
- **Resume/state** après crash (reprise du recon).
- **Notifications** (Telegram/Discord) quand un finding tombe.

## 🧱 P3 — avancé
- DNS brute-force (puredns/shuffledns + SecLists ; pc1/pc3 ont déjà `/usr/share/seclists/`).
- Cloud buckets exposés (S3/GCS/Azure) via favicon/JS/wayback.
- Détection de changement de scope (asset retiré → stop obligatoire).
- Détection de duplicates avant soumission (recherche disclosed H1/Bugcrowd).
- OPSEC : secrets/API keys hors repo (`.env`), masquage PII automatique dans les preuves.
- Templates de rapport par classe de vuln (XSS/IDOR/SSRF) avec CWE pré-rempli.
