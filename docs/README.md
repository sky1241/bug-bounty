# Documentation — bug-bounty

Index de la doc du projet.

| Document | Contenu |
|----------|---------|
| [REPORTING_PROTOCOL.md](REPORTING_PROTOCOL.md) | Protocole de rapport + checklist + **Phase 0 anti-faux-positif** (à suivre à l'identique pour chaque bug) |
| [AUDIT_SCOPE_GUARD.md](AUDIT_SCOPE_GUARD.md) | Audit adversarial du scope guard (29 fuites trouvées/corrigées) + limitations connues |
| [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) | Structure-type **réplicable pour chaque projet** (isolation Docker + journal + doc) |

## Modules (`bb/`)

| Module | Rôle |
|--------|------|
| `scope.py` | **Cœur légal** : décide si une cible est in-scope (audité) |
| `sources.py` | Récupération des feeds de programmes (sans auth) |
| `aggregate.py` | Normalisation 5 plateformes + filtre `--starter` |
| `recon.py` | Pipeline recon hybride (PD ou fallback Python), in-scope only |
| `report.py` | Générateur de rapport (refuse si non validé) |
| `journal.py` | **Le « dictionnaire »** : historique append-only des tests |
| `cli.py` | CLI : `list / scope / update / recon / report / journal` |

## Isolation Docker

Tout tourne dans un conteneur dédié au projet (voir [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)) :

```bash
docker compose run --rm bb list --starter --fr
docker compose run --rm bb recon example.com --program <nom> --scan
docker compose run --rm bb journal
```
