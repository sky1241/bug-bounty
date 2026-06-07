#!/usr/bin/env bash
# CI local — anti-bullshit : chaque étape est exécutée et doit VRAIMENT passer.
# tests → docker build → tests DANS le container → fleet health.
# Usage: bash scripts/ci.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
fail() { echo "❌ CI FAIL: $1"; exit 1; }

echo "==[1/5]== tests unitaires (hôte)"
python3 -m pytest -q || fail "pytest hôte"

echo "==[2/5]== build de l'image Docker"
docker build -q -t bug-bounty:ci . >/dev/null || fail "docker build"

echo "==[3/5]== tests unitaires DANS le container (isolation solide)"
docker run --rm --entrypoint sh bug-bounty:ci -c 'cd /app && python -m pytest -q' >/dev/null 2>&1 \
  || fail "tests container"

echo "==[4/5]== health de la fleet (pc1/pc3 workers + pc2 rapports)"
bash scripts/fleet_health.sh || fail "fleet health"

echo "==[5/5]== tests unitaires SUR les workers Kali (pc1/pc3)"
bash scripts/fleet_test.sh || fail "tests fleet"

echo ""
echo "✅ CI OK — code + container + fleet (Kali testés) opérationnels"
