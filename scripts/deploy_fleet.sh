#!/usr/bin/env bash
# Déploie le repo + les outils recon sur les nœuds workers (cousins Kali).
# Sync depuis sky-master (pas besoin d'auth GitHub). Non destructif.
# Usage: bash scripts/deploy_fleet.sh [pc1 pc3 ...]
set -uo pipefail

SRC="$HOME/Applications/bug-bounty/"
if [ $# -gt 0 ]; then NODES=("$@"); else NODES=(pc1 pc3); fi

for node in "${NODES[@]}"; do
  echo "========== $node =========="
  echo "[$node] sync code…"
  # NB: pas de pipe sur rsync (sinon l'exit code de rsync est masqué par tail = faux positif).
  if rsync -az \
       --exclude '.git' --exclude '.muninn' --exclude 'data/programs/*.json' \
       --exclude 'journal/*.jsonl' --exclude 'engagements/*' --exclude '__pycache__' \
       --exclude '.venv' --exclude '.forge' --exclude '*.pyc' \
       "$SRC" "$node:bug-bounty/" 2>/dev/null; then
    echo "[$node]   rsync OK"
  else
    echo "[$node]   rsync indisponible → fallback scp"
    ssh "$node" 'mkdir -p ~/bug-bounty'
    if scp -q -r "${SRC}bb" "${SRC}scripts" "${SRC}templates" "${SRC}requirements.txt" \
           "${SRC}pyproject.toml" "$node:bug-bounty/"; then
      echo "[$node]   scp OK"
    else
      echo "[$node]   ❌ scp ÉCHEC"; continue
    fi
  fi

  echo "[$node] install outils ProjectDiscovery…"
  ssh "$node" 'cd ~/bug-bounty && bash scripts/install_tools.sh 2>&1 | tail -8'

  echo "[$node] python requests…"
  ssh "$node" 'python3 -m pip install --user --quiet requests 2>/dev/null \
    || python3 -m pip install --user --break-system-packages --quiet requests 2>&1 | tail -1 \
    || echo "(requests déjà présent ou pip indisponible)"'

  echo "[$node] vérification (outils détectés par le code) :"
  ssh "$node" 'cd ~/bug-bounty && export PATH="$HOME/.local/bin:$PATH" && \
    PYTHONPATH=. python3 -c "from bb import recon; print({t:bool(recon.pd_path(t)) for t in (\"subfinder\",\"httpx\",\"nuclei\")})" 2>&1'
done
echo "===== déploiement terminé ====="
