#!/usr/bin/env bash
# Scan matinal: rafraîchit la base + détecte les NOUVELLES offres, et TE PRÉVIENT si trouvé.
cd "$(dirname "$0")/.." || exit 1
export PATH="$HOME/.local/bin:$PATH"
TS="$(date '+%Y-%m-%d %H:%M')"
TG="$HOME/bin/tg-send.sh"  # alerte Telegram (retry/fallback, source ~/.config/fleet-bot/.env) → notif sur le tél, partout
UPD="$(python3 -m bb update 2>&1)"
printf '%s\n' "$UPD" >> journal/morning_scan.log
NEW="$(python3 -m bb new 2>&1)"
{ echo "===== $TS ====="; echo "$NEW"; } >> journal/morning_scan.log

# 1) Sources en échec (ex: YWH ConnectionError) => trou de couverture => on alerte.
FAIL="$(printf '%s\n' "$UPD" | grep -iE 'ÉCHEC|echec' || true)"
if [ -n "$FAIL" ]; then
  printf '[%s] ⚠️ SOURCE(S) EN ÉCHEC (couverture incomplète, relance `bb update`):\n%s\n' "$TS" "$FAIL" > SOURCE_EN_ECHEC.txt
  DISPLAY=:0 notify-send -u critical "⚠️ Bug Bounty — source en échec ce matin" "$FAIL" 2>/dev/null || true
  [ -x "$TG" ] && "$TG" "⚠️ Bug Bounty — source(s) en échec (couverture incomplète, relance bb update) :
$FAIL" >/dev/null 2>&1 || true
else
  rm -f SOURCE_EN_ECHEC.txt
fi

# 2) Si bb new ne dit PAS "aucune nouvelle" => il y a du frais => on alerte Sky.
if ! printf '%s' "$NEW" | grep -qi "aucune nouvelle"; then
  printf '[%s] 🎯 NOUVELLES OFFRES BUG BOUNTY:\n%s\n' "$TS" "$NEW" > NOUVELLES_OFFRES.txt
  DISPLAY=:0 notify-send "🎯 Bug Bounty — nouvelles offres fraîches !" "$NEW" 2>/dev/null || true
  [ -x "$TG" ] && "$TG" "🎯 Bug Bounty — nouvelles offres fraîches ($TS) :
$NEW" >/dev/null 2>&1 || true
fi
