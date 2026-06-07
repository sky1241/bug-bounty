# bug-bounty

Outillage personnel de bug bounty pour débutant. Deux modules :

1. **Agrégateur de programmes** — scanne les sources publiques (EN + FR), liste les
   programmes ouverts avec leur **scope** et leur **prime**, filtre les cibles
   « faciles débutant ».
2. **Pipeline recon → scan → rapport** — sur les cibles **in-scope uniquement**.

## ⚠️ Règle légale — non négociable

Ce projet ne touche **QUE** des cibles explicitement autorisées par le scope d'un
programme de bug bounty (ou tes propres assets). Scanner une cible hors-scope =
accès non autorisé = illégal (art. 323 CP en France, équivalent ailleurs) + ban
plateforme. Le module [`bb/scope.py`](bb/scope.py) est le garde-fou : toute cible
passe par lui avant d'être touchée, et **out-of-scope l'emporte toujours**.

## État

🚧 En construction. Le cœur légal (scope guard + tests) est posé. Les modules
d'agrégation et de recon sont en cours de design, sur la base d'une recherche
vérifiée des sources et feeds disponibles.

## Structure

```
bb/            # package Python
  scope.py     # garde-fou in-scope (coeur légal)
tests/         # tests unitaires
data/programs/ # cache local des scopes téléchargés (gitignored)
```

## Dev

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest tests/ -q
```
