# Audit adversarial du scope guard

Le scope guard ([`bb/scope.py`](../bb/scope.py)) est le **cœur légal** : il décide si une
cible est in-scope. Une fuite (autoriser une cible hors-scope) = scan illégal. Ce
composant a donc été soumis à un audit adversarial avant de bâtir le recon dessus.

## Méthode

6 classes de contournement explorées en parallèle par des agents, générant **71 cas
de test concrets**, puis **exécutés contre le vrai code** (aucun verdict sur parole).
Reproductible :

```bash
python tests/audit/replay.py tests/audit/cases.json
```

## Résultat initial : 29 fuites hors-scope, 0 crash

Racines identifiées :

| # | Vecteur | Exemple |
|---|---------|---------|
| 1 | Wildcard `*` → `.+` traversait les points | `*.com` matchait `evil.com` ; `example.*` matchait `example.evil.com` |
| 2 | Injection regex via données de feed | `a.example.com\|evil.com` autorisait `evil.com` |
| 3 | Normalisation faible | `evil.com\@allowed.com` (backslash) et `admin.x.com\nshop...` (newline) trompaient `urlparse` |
| 4 | Out-of-scope perdu à la construction | asset typé `mobile` ou `"x.com (do not test)"` était droppé |
| 5 | Patterns catch-all acceptés | un asset `*` ouvrait tout internet |

## Corrections

**Dans `Scope` (vecteurs intrinsèques)** — couvert par `tests/test_scope.py` :
- `normalize_host` durci : rejet de `\`, espace, tab, newline ; validation stricte du
  hostname (pas d'unicode/homoglyphe) ; canonicalisation des IP (decimal-int, hex, octal, IPv6).
- `*` → `[^.]+` : **ne traverse plus jamais les points** (un `*` = un label).
- Préfixe `*.` → `(?:[^.]+\.)+` (sous-domaines multi-niveaux), apex **non** couvert (conservateur).
- Rejet : catch-all (`*`, `*.tld` à 1 label), `|` hors parenthèses, parenthèses
  déséquilibrées, `*` collé en début de label (`*example.com`), port-wildcard `:*`.
- Wildcards partiels légitimes préservés (`api-*.example.com`).

**À la construction (`aggregate._in_patterns` / `_out_patterns`)** — couvert par `tests/test_aggregate.py` :
- **in-scope conservateur** : seuls les assets web, patterns validés par `_compile_pattern`.
- **out-of-scope inclusif** : type ignoré, extraction de hosts même dans des valeurs
  sales (`x.com (do not test)`, `a.com|b.com`), apex ajouté pour les `*.x`, port `:*` neutralisé.

## Résultat après : 0 fuite exploitable en production

Les fuites encore visibles via `replay.py` le sont au niveau **`Scope` brut** ; elles
sont **neutralisées à la construction** (`parse_program`). Vérifiable :
`tests/test_aggregate.py::test_construction_out_of_scope_is_inclusive` et
`::test_construction_rejects_catchall_from_feed`.

## Limitations connues (assumées, à vérifier manuellement)

1. **Scope au niveau host, pas path.** Un scope path-restreint (`example.com/only-this`)
   est traité comme tout l'host `example.com`. → relire le scope du programme à la main
   quand il est path-restreint.
2. **CIDR / IPv6 en out-of-scope : support partiel** (IP exacte, pas une plage `/8`).
3. **Wildcard au milieu en out-of-scope** (`admin.*.example.com`) ne couvre pas l'apex
   `admin.example.com` (qui reste in-scope via le wildcard principal).
