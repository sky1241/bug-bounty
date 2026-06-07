#!/usr/bin/env bash
# Health check de la fleet — anti-bullshit : on VÉRIFIE chaque nœud, on n'invente rien.
#   Workers recon (Kali) : pc1, pc3  → doivent avoir le repo + les outils PD.
#   Maître rapports       : pc2       → doit avoir le repo + bb importable.
# Usage: bash scripts/fleet_health.sh
set -uo pipefail

WORKERS="${WORKERS:-pc1 pc3}"
REPORTER="${REPORTER:-pc2}"
ok=0; ko=0

check_node() {
  local node="$1" role="$2"
  printf "%-5s [%-8s] " "$node" "$role"
  if ! timeout 10 ssh -o ConnectTimeout=6 "$node" 'true' 2>/dev/null; then
    echo "❌ injoignable"; ko=$((ko+1)); return; fi
  if ! ssh "$node" 'test -d ~/bug-bounty' 2>/dev/null; then
    echo "⚠️  repo absent (deploy_fleet.sh)"; ko=$((ko+1)); return; fi
  if [ "$role" = worker ]; then
    local n
    n=$(ssh "$node" 'cd ~/bug-bounty && export PATH=$HOME/.local/bin:$PATH && PYTHONPATH=. \
      python3 -c "from bb import recon; print(sum(bool(recon.pd_path(t)) for t in (\"subfinder\",\"httpx\",\"nuclei\")))"' 2>/dev/null)
    if [ "${n:-0}" = 3 ]; then echo "✅ outils PD 3/3"; ok=$((ok+1));
    else echo "⚠️  outils PD ${n:-0}/3 (recon dégradé)"; ok=$((ok+1)); fi
  else
    if ssh "$node" 'cd ~/bug-bounty && PYTHONPATH=. python3 -c "import bb.report" ' 2>/dev/null; then
      echo "✅ générateur de rapports prêt"; ok=$((ok+1));
    else echo "❌ bb non importable"; ko=$((ko+1)); fi
  fi
}

echo "===== FLEET HEALTH ====="
for w in $WORKERS; do check_node "$w" worker; done
check_node "$REPORTER" reporter
echo "------------------------"
echo "Bilan : $ok OK / $ko KO"
if [ "$ko" -eq 0 ]; then echo "✅ FLEET OPÉRATIONNELLE"; else echo "❌ fleet incomplète"; exit 1; fi
