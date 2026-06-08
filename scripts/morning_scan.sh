#!/usr/bin/env bash
# Scan matinal: rafraîchit la base + liste les NOUVELLES offres dans journal/morning_scan.log
cd "$(dirname "$0")/.." || exit 1
export PATH="$HOME/.local/bin:$PATH"
{ echo "===== $(date '+%Y-%m-%d %H:%M') ====="
  python3 -m bb update
  echo "--- NOUVELLES OFFRES ---"
  python3 -m bb new
} >> journal/morning_scan.log 2>&1
