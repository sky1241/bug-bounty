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

# 3) Source amont GELÉE ? arkadiyt/bounty-targets-data commit ~toutes les 30 min.
#    Plus de commit depuis SOURCE_MAX_AGE_H heures => scraper mort/en panne => angle
#    mort (bb update réussit mais relit un cache figé) => on alerte UNE seule fois.
SOURCE_MAX_AGE_H=6
LAST="$(curl -s --max-time 15 --retry 2 --retry-delay 3 'https://api.github.com/repos/arkadiyt/bounty-targets-data/commits?per_page=1' | jq -r '.[0].commit.committer.date' 2>/dev/null)"
# FIX faux positif : ne traiter QUE si LAST est une vraie date ISO. Si le fetch échoue,
# LAST est vide et `date -d ""` renvoie MINUIT du jour (exit 0, PAS une erreur) => faux
# "âge depuis minuit" => fausse alerte qui tombe vers 6h du matin. Le garde regex tue ce
# chemin : fetch KO / rate-limit / "null" => pas une date ISO => on saute (zéro alerte).
if printf '%s' "$LAST" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}'; then
  EPOCH="$(date -d "$LAST" +%s 2>/dev/null)"
  AGE_H=$(( ( $(date +%s) - EPOCH ) / 3600 ))
  if [ "$AGE_H" -ge "$SOURCE_MAX_AGE_H" ]; then
    MSG="⚠️ Source bug-bounty GELÉE : arkadiyt/bounty-targets-data n'a pas bougé depuis ${AGE_H}h (normal ~30 min). Le mec/scraper est peut-être mort → tu rates des offres sans le savoir. Vérifie : https://github.com/arkadiyt/bounty-targets-data/commits"
    if [ ! -f SOURCE_GELEE.txt ]; then   # 1re détection seulement => pas de spam à chaque scan
      DISPLAY=:0 notify-send -u critical "⚠️ Bug Bounty — source gelée (${AGE_H}h)" "$MSG" 2>/dev/null || true
      [ -x "$TG" ] && "$TG" "$MSG" >/dev/null 2>&1 || true
    fi
    printf '[%s] %s\n' "$TS" "$MSG" > SOURCE_GELEE.txt
  else
    rm -f SOURCE_GELEE.txt   # source vivante => on efface le flag (un futur gel re-alertera)
  fi
fi
