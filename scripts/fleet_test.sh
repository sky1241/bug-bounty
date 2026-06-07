#!/usr/bin/env bash
# Lance la suite de tests SUR les workers Kali (pc1/pc3), avec le code à jour.
# Anti-bullshit : on synchronise puis on exécute vraiment, on lit le compte de passés.
# Usage: bash scripts/fleet_test.sh
set -uo pipefail
cd "$(dirname "$0")/.."
WORKERS="${WORKERS:-pc1 pc3}"
fail=0

for n in $WORKERS; do
  printf "[%s] sync + pytest… " "$n"
  rsync -az --exclude '__pycache__' bb/ "$n:bug-bounty/bb/" 2>/dev/null
  rsync -az --exclude '__pycache__' tests/ "$n:bug-bounty/tests/" 2>/dev/null
  rsync -az pyproject.toml "$n:bug-bounty/" 2>/dev/null
  # On se fie au CODE DE RETOUR de pytest (0 = tout passe), pas au texte (fragile :
  # -qq masque le résumé, et le \r de la ligne de points piège `tail`).
  out=$(ssh "$n" 'cd ~/bug-bounty && python3 -m pytest >/tmp/bb_pt.log 2>&1; echo "RC:$?"; \
                  grep -aoE "[0-9]+ (passed|failed|error)[a-z ,0-9.]*" /tmp/bb_pt.log | tail -1')
  rc=$(printf '%s' "$out" | grep -oE 'RC:[0-9]+' | cut -d: -f2)
  summary=$(printf '%s\n' "$out" | grep -v '^RC:' | tail -1)
  echo "${summary:-(résumé indispo)} [exit ${rc:-?}]"
  if [ "${rc:-1}" -ne 0 ]; then echo "  ❌ $n : tests KO (exit ${rc:-?})"; fail=1; fi
done

if [ "$fail" -eq 0 ]; then echo "✅ tests OK sur tous les workers Kali"; else echo "❌ tests KO"; exit 1; fi
