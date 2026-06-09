# PLAN DE BATAILLE — Bug Bounty (Sky)

> Objectif : soumettre un VRAI bug, proprement. Pas de faux positif, pas de bullshit.

## ⚠️ La vérité, sans filtre (à lire une fois)
- Les bugs **faciles** des gros programmes connus (Arlo, Logitech…) sont **souvent déjà pris**. Si on le trouve avec l'IA, d'autres aussi. **T'as raison là-dessus.**
- Donc 2 façons de gagner : **(A)** viser des programmes **FRAIS** (peu de rapports, récents), **(B)** chercher les bugs que les scanners **ratent** (logique métier, IDOR de niche, chaînage) — là, l'humain bat le scanner.
- Attentes réalistes : **1er bug = quelques jours** de pratique. **600€/mois = après quelques semaines.** C'est un métier, pas un coup de chance.

---

## CHUNK 0 — Setup propre (une fois pour toutes) ✅ en cours
- [x] Chrome navigateur par défaut
- [ ] Burp : proxy OK + son navigateur intégré capture le trafic
- [ ] Méthode de capture validée (au choix : **F12 → Network** dans Chrome, OU navigateur Burp)
- **Règle** : pour CAPTURER, F12 → Network suffit. Pour REJOUER/modifier une requête, Burp Repeater (ou "Copy as cURL").

## CHUNK 1 — Apprendre Burp/cURL EN RÉEL (Sky refuse les labs démo — acté)
- [ ] On apprend l'outil **directement sur Arlo** (ton compte A, cible réelle), pas sur des labs d'entraînement
- [ ] Capturer une vraie requête `/hmsweb/users/profile` : F12 → Network, filtre `hmsweb`, clic droit → **Copy as cURL**
- [ ] La **rejouer en changeant un ID** : soit Burp Repeater (puisque tu veux l'apprendre), soit cURL dans le terminal (plus simple)
- [ ] À la fin tu sais : capturer, repérer l'ID dans la requête, le modifier, relire la réponse
- **Pourquoi ça marche en réel** : sur TON compte tu ne risques rien, et l'API Arlo EST le terrain. On apprend en chassant.

## CHUNK 2 — Chasse Arlo (la piste actuelle : IDOR sur /hmsweb/users/)
- [ ] **Compte A** (déjà créé) : capturer les requêtes `/hmsweb/users/...` (F12 → Network, filtre `hmsweb`)
- [ ] Endpoints testables **sans appareil** : `profile`, `account`, `locations`, `serviceLevel/v4`, `friends`
- [ ] **Compte B = la CIBLE du test, PAS un compte démo.** Un IDOR cross-compte = « A lit les données de B ». Sans B, le bug est **impossible à prouver**. C'est le PoC lui-même, pas un exercice d'école.
- [ ] Test IDOR : prendre une requête de **A**, remplacer l'ID/ressource par celui de **B** → si données de B visibles = **IDOR**
- [ ] ⚠️ Arlo : **scanners auto INTERDITS** → test manuel uniquement. PoC = **cross-compte** (A lit les données de B).

## CHUNK 3 — Si Arlo donne rien → programmes FRAIS (avec la fleet)
- [ ] Claude sélectionne **2-3 programmes frais** (peu de rapports, scope web large, scanners autorisés)
- [ ] Fleet : **1 programme par PC** (pc1/pc2/pc3), recon + analyse
- [ ] Tester les bugs accessibles (open redirect, IDOR, XSS) manuellement

## CHUNK 4 — Validation + soumission (la règle d'or)
- [ ] Reproduire le bug **3 fois** (anti faux positif)
- [ ] **PoC propre** : lien cliquable OU req+resp cross-compte
- [ ] Claude rédige le **rapport pro** (impact, étapes, CVSS)
- [ ] **Soumettre** sur la plateforme

---

## Qui fait quoi
- **Claude** : recon, analyse des requêtes, identification des candidats bugs, validation cross-check, rédaction des rapports, orchestration fleet.
- **Sky** : les clics dans le navigateur (se connecter, naviguer, rejouer dans Burp), créer les comptes, soumettre. Claude guide à chaque étape.
- **Jamais** : hors-scope, faux positif soumis, scanner là où c'est interdit.
