#!/usr/bin/env bash
# Lance une commande bb dans un CONTENEUR DÉDIÉ à un projet (isolation système totale).
# Chaque engagement = son conteneur (bb-<slug>) + son workspace isolé (/work).
#
# Usage : bash scripts/project_run.sh <slug-engagement> [commande bb...]
#   ex : bash scripts/project_run.sh xelians-blackbox-program doctor
#        bash scripts/project_run.sh xelians-blackbox-program scope decathlon
#        bash scripts/project_run.sh xelians-blackbox-program \
#             recon www.example.com --scope-file /work/scope.json --json --out /work/recon/out.json
set -uo pipefail
cd "$(dirname "$0")/.."

SLUG="${1:?usage: project_run.sh <slug-engagement> [commande bb...]}"; shift || true
ENG="engagements/$SLUG"
IMG="bug-bounty:latest"

if [ ! -d "$ENG" ]; then
  echo "❌ Engagement '$SLUG' introuvable ($ENG)."
  echo "   Crée-le d'abord : python3 -m bb scan \"<programme>\" --go"
  exit 1
fi
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "Image $IMG absente → build…"
  docker build -q -t "$IMG" . >/dev/null || { echo "❌ build KO"; exit 1; }
fi

mkdir -p "$ENG/recon" "$ENG/findings"
# Conteneur dédié au projet : workspace isolé (/work = le dossier d'engagement),
# cache des feeds en LECTURE SEULE, réseau propre au conteneur (pas --network host).
exec docker run --rm --name "bb-$SLUG" \
  -v "$(pwd)/$ENG:/work" \
  -v "$(pwd)/data:/app/data:ro" \
  -w /app \
  "$IMG" "${@:-doctor}"
