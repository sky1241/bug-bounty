# bug-bounty

Outillage personnel de bug bounty pour débutant. **In-scope only.**

1. **Agrégateur de programmes** — scanne les sources publiques (EN + FR), liste les
   programmes ouverts avec **scope** + **prime**, filtre les cibles « faciles débutant ».
2. **Pipeline recon → probe → scan** — sur les cibles **in-scope uniquement**.
3. **Générateur de rapport** — protocole standardisé + validation anti-faux-positif obligatoire.

## ⚠️ Règle légale — non négociable

Ce projet ne touche **QUE** des cibles explicitement autorisées par le scope d'un
programme (ou tes propres assets). Scanner hors-scope = illégal + ban. Le module
[`bb/scope.py`](bb/scope.py) est le garde-fou (audité : voir
[docs/AUDIT_SCOPE_GUARD.md](docs/AUDIT_SCOPE_GUARD.md)) ; il est ré-appliqué entre chaque
étape du recon.

## Commandes

```bash
python -m bb update                       # télécharge les feeds de programmes
python -m bb list --starter --fr          # programmes FR triés anti-saturation
python -m bb list --beginner --limit 20   # programmes débutant (cash + web + scope)
python -m bb scope <nom>                  # affiche le scope exact d'un programme

# Recon (in-scope only). --program charge le scope d'un vrai programme.
python -m bb recon example.com --program <nom>           # recon + probe + checks
python -m bb recon example.com --program <nom> --scan    # + nuclei (si installé)
python -m bb recon example.com --authorized --passive-only   # OSINT, zéro paquet actif

# Rapport (refuse tant que la Phase 0 anti-faux-positif n'est pas validée)
python -m bb report finding.json --program <nom>
```

### Conteneur isolé par projet

Chaque engagement peut tourner dans son **propre conteneur** Docker (isolation système
totale entre projets) — workspace = le dossier d'engagement, données en lecture seule :

```bash
python -m bb scan "<programme>" --go                  # crée engagements/<slug>/
bash scripts/project_run.sh <slug> doctor             # conteneur dédié bb-<slug>
bash scripts/project_run.sh <slug> recon www.cible.tld --scope-file /work/scope.json --out /work/recon/out.json
```

Le recon est **hybride** : il utilise subfinder/httpx/nuclei de **ProjectDiscovery**
s'ils sont réellement installés (vérifié, pas juste un binaire homonyme), sinon il
bascule sur un fallback pur Python (crt.sh + hackertarget pour les sous-domaines,
`requests` pour le probe). Les sources en échec sont **remontées**, jamais avalées.

## Rapports

Tout rapport suit [docs/REPORTING_PROTOCOL.md](docs/REPORTING_PROTOCOL.md) et son
[template](templates/report_template.md). La **Phase 0** (3 passes anti-faux-positif)
est obligatoire — `bb/report.py` refuse de générer sinon.

## Structure

```
bb/            scope.py · aggregate.py · sources.py · recon.py · report.py · cli.py
docs/          REPORTING_PROTOCOL.md · AUDIT_SCOPE_GUARD.md
templates/     report_template.md
tests/         33 tests + audit/ (replay du scope guard)
data/programs/ cache local des feeds (gitignored)
```

## Dev

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. python -m pytest tests/ -q
```
