# Structure-type d'un projet (réplicable)

Objectif : **chaque projet est isolé des autres** (son repo, son conteneur Docker, son
journal) et documenté **de la même façon**. On reproduit cette structure pour tout
nouveau projet.

## Arborescence standard

```
<projet>/
├── Dockerfile            # image dédiée au projet (isolation des dépendances/outils)
├── docker-compose.yml    # service + volumes persistants (data, journal, output)
├── .dockerignore
├── .gitignore
├── requirements.txt
├── README.md             # quoi + comment lancer
├── <package>/            # le code (ici: bb/)
├── tests/                # tests (+ tests/audit/ si audit sécu)
├── docs/                 # doc structurée
│   ├── README.md         # index de la doc
│   ├── REPORTING_PROTOCOL.md   # protocole (si le projet produit des rapports)
│   └── ...               # autres docs spécifiques
├── data/                 # caches re-téléchargeables (gitignored)
└── journal/              # le « dictionnaire » : historique des tests (gitignored)
    └── log.jsonl
```

## Les 3 garanties

1. **Isolation (Docker).** Tout tourne dans le conteneur du projet — outils et
   dépendances n'existent que là, jamais sur l'hôte ni partagés entre projets.
   ```bash
   docker compose run --rm <service> <commande>      # compose v2
   docker-compose run --rm <service> <commande>      # compose v1 (équivalent)
   ```
2. **Historique (journal).** Chaque projet tient son `journal/log.jsonl` : tout ce
   qu'on a testé, les bugs, les faux positifs écartés, les notes de debug. Consultable
   (`bb journal list / summary`). Local par défaut (peut contenir des données
   sensibles) ; à versionner seulement si tu le décides.
3. **Doc identique.** `docs/` avec un `README.md` d'index + les protocoles. Même
   squelette pour chaque projet → on s'y retrouve partout pareil.

## Pour démarrer un nouveau projet

1. Copier le squelette ci-dessus (Dockerfile, compose, docs/, journal/, .gitignore).
2. `git init` + premier commit.
3. `docker-compose build` une fois.
4. Travailler **uniquement** via le conteneur → séparation garantie.
