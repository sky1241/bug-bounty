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
  res=$(ssh "$n" 'cd ~/bug-bounty && python3 -m pytest -q 2>&1 | tail -1')
  echo "$res"
  if ! echo "$res" | grep -q "passed" || echo "$res" | grep -q "failed\|error"; then
    echo "  ❌ $n : tests KO"; fail=1
  fi
done

if [ "$fail" -eq 0 ]; then echo "✅ tests OK sur tous les workers Kali"; else echo "❌ tests KO"; exit 1; fi
