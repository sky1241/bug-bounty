#!/usr/bin/env bash
# Test E2E du pipeline COMPLET sur une cible de TEST sûre (example.com, RFC 2606).
# Protocole de validation reproductible : si ça passe, tout le pipeline est sain.
# Zéro paquet actif vers une vraie cible (recon en --passive-only).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
PY="python3 -m bb"
fail() { echo "❌ ÉCHEC: $1"; exit 1; }

echo "==[1/6]== doctor (outils installés ?)"
$PY doctor || fail "doctor"

echo "==[2/6]== tests unitaires"
python3 -m pytest -q >/dev/null 2>&1 || fail "pytest"
echo "  OK"

echo "==[3/6]== scan (verdict sur un programme connu)"
$PY scan "Xelians" 2>&1 | head -1 || fail "scan"

echo "==[4/6]== recon passif in-scope (example.com, zéro paquet actif)"
echo '{"in_scope":["*.example.com"],"out_of_scope":[]}' \
  | timeout 180 $PY recon example.com --scope-file - --passive-only --json 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
print(f'  in-scope={d[\"in_scope\"]} rejetes={d[\"rejected\"]} urls={d.get(\"urls\",0)}'); \
assert d['in_scope']>=1, 'recon vide'" || fail "recon"

echo "==[5/6]== rapport : DOIT refuser si validation incomplète (anti-faux-positif)"
echo '{"finding":{"title":"E2E","asset_url":"https://example.com"},"validation":{"repro":false}}' > /tmp/e2e_finding.json
if $PY report /tmp/e2e_finding.json >/dev/null 2>&1; then fail "le rapport aurait dû refuser"; fi
echo "  refus correct ⛔"

echo "==[6/6]== journal (historique alimenté)"
$PY journal >/dev/null 2>&1 || fail "journal"
echo "  OK"

echo ""
echo "✅ E2E PIPELINE OK — scan → recon in-scope → garde-fou → rapport validé → journal"
