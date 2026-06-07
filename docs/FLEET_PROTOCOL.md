# Protocole de recon distribué (fleet)

Objectif : **recon plus rapide et plus intelligent** en répartissant le travail sur
la fleet, sans jamais sortir du scope.

## Rôles

| Nœud | Rôle |
|------|------|
| **sky-master** | Orchestrateur : choisit le programme, dérive le scope + les domaines-graines, distribue, agrège, journalise |
| **pc1** (Kali) | Worker recon |
| **pc3** (Kali) | Worker recon |
| (local) | Worker recon (sky-master peut aussi exécuter une part) |

## Flux

```
programme ──► scope (bb/scope.py) ──► domaines-graines (fleet.seed_domains)
                                          │
                                  shards pondérés (fleet.plan, weight = puissance machine)
                                          │
              ┌───────────────────────────┼───────────────────────────┐
            pc1                          pc3                          local
   bb recon <shard> --scope-file -   (idem)                        (idem)   ← EN PARALLÈLE
   (scope envoyé en stdin)                                                   (--json sur stdout)
              └───────────────────────────┼───────────────────────────┘
                                          ▼
                          sky-master agrège + déduplique + journalise (bb journal)
```

## Garde-fou (inchangé en distribué)

Chaque worker reçoit le **scope explicite** (via `--scope-file -`, en stdin) — il
n'a pas besoin du cache feeds et reste strictement in-scope (`Scope.allows` ré-appliqué
à chaque étape sur chaque nœud). Aucune IP hardcodée : on passe par les **alias SSH**.

## Optimisations

- **Parallélisme** : N workers → ~÷N sur le temps de recon.
- **Pondération** : `Node(name, weight=...)` — une machine plus rapide reçoit plus de
  cibles (`fleet.plan` répartit au prorata du poids).
- **Sources passives multiples** (subfinder + crt.sh + hackertarget) → meilleure couverture.
- **Dédup à l'agrégation** : les sous-domaines vus par plusieurs nœuds ne sont comptés qu'une fois.

## Lancer

```bash
bb fleet <programme> --nodes pc1,pc3,local           # recon distribué
bb fleet <programme> --nodes pc1,pc3 --scan          # + nuclei sur les workers
```

## Prérequis sur chaque worker

1. Le repo dans `~/bug-bounty` (sync depuis sky-master ou clone).
2. Les outils PD : `bash scripts/install_tools.sh` (→ `~/.local/bin`).
3. `python3 -m pip install requests`.

## Garder les listes à jour

Les feeds de programmes vieillissent. Sur sky-master :

```bash
bb update         # à lancer régulièrement (ex: cron quotidien) pour des scopes frais
```

## État

- ✅ Logique de distribution (`bb/fleet.py`) + orchestrateur (`bb fleet`) + mode worker — testés.
- ✅ Outils PD (subfinder/httpx/nuclei) déployés sur **pc1 et pc3** (`scripts/deploy_fleet.sh`).
- ✅ **Fleet prouvée end-to-end** : pc1 (9393 in-scope) et pc3 (3204 in-scope) exécutent le
  recon à distance sur example.com, scope respecté, JSON retourné.
- ✅ Feeds rafraîchis quotidiennement (cron `bb update` sur sky-master, 06:30).
