# Protocole de validation croisée (anti-hallucination)

> But : ne **jamais** présenter un finding halluciné ou un faux positif. On ne fait pas
> confiance à un seul résultat (ni à un seul agent, ni à un seul nœud, ni au LLM seul).

Issu d'un deep audit méthodo (fact-checké). Brique de code : [`bb/crossval.py`](../bb/crossval.py)
(`bb crossval <prog> --nodes pc1,pc3`).

## Les 9 règles

1. **Consensus 2 nœuds INDÉPENDANTS.** Même cible sur **pc1 ET pc3**, séparément (binaires,
   wordlists, resolvers DNS distincts — sinon le « consensus » est un faux jumeau). On
   normalise chaque sortie avant de comparer.
2. **Anti-consensus-circulaire (règle Sky).** Ne **jamais** croiser deux nœuds qui partagent
   la même source de vérité. pc1/pc3 OK (Kali indépendants). **JAMAIS** sky-master ↔ pc2 sur
   du critique = preuves circulaires.
3. **Validation ACTIVE > vote textuel.** Quand l'outil sait re-vérifier, ça prime sur le
   consensus : `trufflehog --results=verified` (teste la clé en live), `nuclei`
   matcher-status=true, **callback interactsh** (un hit DNS/HTTP = preuve irréfutable d'un blind).
4. **3 paliers de confiance.**
   - **CONFIRMÉ** : vu sur ≥2 nœuds **ET** re-validé à l'exécution (verified=true / callback).
   - **À VÉRIFIER** : consensus textuel sans validation active → revue manuelle.
   - **SUSPECT** : vu sur 1 seul nœud → delta, ne pas s'y fier.
5. **Inversion des rôles (adversarial).** Après consensus, **pc2** (vérificateur dédié, jamais
   le producteur) reçoit **uniquement** le finding + la preuve brute, et a pour mission de le
   **réfuter**. S'il n'y arrive pas, le finding tient.
6. **Self-consistency** pour les outils non-déterministes (ffuf, katana, naabu rate-limité) :
   rejouer **N=3** sur le même nœud, garder ce qui apparaît dans **≥2/3** runs.
7. **Anti-hallucination du LLM lui-même.** L'agent ne raisonne **jamais** sur du texte libre —
   il parse le **JSONL champ par champ** et valide chaque ligne (full-id, matcher-status,
   verified…). C'est pourquoi on privilégie les outils à sortie **JSON/JSONL** structurée.
8. **Delta loggé, pas jeté.** Chaque divergence inter-nœud → `delta.jsonl`
   `{clé, present_sur, absent_sur, outil, timestamp}`. Le delta est le signal le plus précieux.
9. **Dedup AVANT consensus** via les hash natifs (`httpx -hash`, favicon mmh3) : deux URLs au
   même hash = même appli → on collapse avant de voter (sinon on « confirme » 5× la même chose).

## Règle d'or anti-faux-positif blind
Aucune vuln **blind** (SSRF/RCE/XXE/SQLi OOB) n'est rapportée **sans un enregistrement de
callback** correspondant dans le JSONL interactsh/nuclei. Pas de callback → « non confirmé »,
jamais un finding. Vérifiable par l'agent : il matche le `full-id`/correlation-id au payload envoyé.

## Outils qui « vérifient » (anti-FP intégré, sortie JSON)
| Outil | Vérifie quoi | Champ de preuve |
|-------|--------------|-----------------|
| trufflehog | secrets/clés (teste en live) | `verified: true` |
| nuclei | vulns (templates + OAST natif) | `matcher-status`, `interaction` |
| interactsh | blind via callback OOB | `protocol`, `full-id` |
| dalfox | XSS (vérif DOM headless) | `jsonl` poc |
| httpx | host vivant + `-hash` (dedup) | `status-code`, `hash` |

## Pièges (vérifiés)
- `asnmap`, `chaos` nécessitent une **clé `PDCP_API_KEY`** (ProjectDiscovery Cloud).
- `uncover` sans clés API ≈ Shodan InternetDB seulement.
- `puredns`, `alterx`, `github-subdomains` : **sortie texte non structurée** → à parser avec prudence.
- Serveurs OOB publics (`oast.pro`) transitent par une infra tierce → self-host pour scope sensible.
