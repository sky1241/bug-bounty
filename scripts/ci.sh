#!/usr/bin/env bash
# CI local — anti-bullshit : chaque étape est exécutée et doit VRAIMENT passer.
# tests → docker build → tests DANS le container → fleet health.
# Usage: bash scripts/ci.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
fail() { echo "❌ CI FAIL: $1"; exit 1; }

echo "==[1/4]== tests unitaires (hôte)"
python3 -m pytest -q || fail "pytest hôte"

echo "==[2/4]== build de l'image Docker"
docker build -q -t bug-bounty:ci . >/dev/null || fail "docker build"

echo "==[3/4]== tests unitaires DANS le container (isolation solide)"
docker run --rm --entrypoint sh bug-bounty:ci -c 'cd /app && python -m pytest -q' >/dev/null 2>&1 \
  || fail "tests container"

echo "==[4/4]== health de la fleet (pc1/pc3 workers + pc2 rapports)"
bash scripts/fleet_health.sh || fail "fleet health"

echo ""
echo "✅ CI OK — code + container + fleet opérationnels"
