#!/usr/bin/env bash
# deploy/push.sh — pusha till GitHub OCH deploya till produktionen i ett svep.
#
# Bakgrund: servern har ingen git-remote (se DEPLOY.md). `git push` lägger koden
# på GitHub men rör inte tjänsten — koden måste kopieras med tar|ssh och tjänsten
# startas om. Det här skriptet gör båda, så glappet "pushad men ej deployad" inte
# kan uppstå igen.
#
# Användning:  ./deploy/push.sh
# Override av server vid behov:  GOOGLEAUTH_SERVER=root@annan.host ./deploy/push.sh

set -euo pipefail

SERVER="${GOOGLEAUTH_SERVER:-root@caddy.sa6bju.se}"
REMOTE_DIR="/opt/googleauth"
SERVICE="googleauth"
HEALTH_URL="http://127.0.0.1:8081/healthz"
LOGIN_URL="https://auth.sa6bju.se/login?next=https://app.sa6bju.se/"

# --- DIN KONTRIBUTION ---------------------------------------------------------
# Rökverifiering efter deploy. Hälsokollen i steg 6 bevisar bara att tjänsten
# LEVER — inte att den nya koden faktiskt nådde prod. Den här funktionen ska
# kontrollera den observerbara EFFEKTEN av deployen.
#
# Konkret just nu: live-/login ska skicka 'prompt=select_account' till Google.
# Kommandot som hämtar redirecten finns nedan; din uppgift är att bestämma:
#   1. Vad räknas som "lyckat"? (vilken sträng måste finnas i svaret)
#   2. Vad ska hända vid MISSLYCKANDE? Avgörande designval:
#        - exit 1 och larma (manuellt ingripande, inget döljs) — enklast, säkrast
#        - försök rulla tillbaka automatiskt — kraftfullt men mer att gå fel
#      För en auth-tjänst där en trasig deploy märks direkt är "fail loud"
#      oftast rätt. Men det är ditt anrop.
verify_deploy() {
  local redirect
  redirect="$(curl -s -o /dev/null -D - "$LOGIN_URL")"

  # Fail-loud: live-/login MÅSTE tvinga kontoväljaren. Saknas parametern kör
  # prod fortfarande gammal kod — larma och avbryt så ingen tror det gick bra.
  if grep -qi 'prompt=select_account' <<<"$redirect"; then
    echo "✓ live-/login skickar prompt=select_account"
    return 0
  fi
  echo "✗ prompt=select_account saknas i live-redirecten — prod kör troligen gammal kod" >&2
  echo "  felsök: ssh ${SERVER} 'journalctl -u ${SERVICE} -n 30 --no-pager'" >&2
  return 1
}
# ------------------------------------------------------------------------------

# Kör från repo-roten oavsett varifrån skriptet anropas.
cd "$(dirname "$0")/.."

# 1. Vägra deploya en smutsig arbetskopia — det vi pushar ska vara det vi deployar.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "✗ Arbetskopian har ocommittade ändringar. Committa eller stasha först." >&2
  exit 1
fi

# 2. Pusha till GitHub (källan-i-sanning).
echo "→ git push"
git push

# 3. Avgör om beroenden ändrades i senaste commit → då måste .venv byggas om på servern.
if git diff --name-only HEAD~1 HEAD | grep -qE '^(pyproject\.toml|uv\.lock)$'; then
  SYNC_DEPS=1
  echo "→ beroenden ändrade i senaste commit — kör uv sync på servern"
else
  SYNC_DEPS=0
fi

# 4. Kopiera koden till servern (samma uteslutningar som DEPLOY.md).
echo "→ kopierar kod till ${SERVER}:${REMOTE_DIR}"
tar czf - --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude=docs . \
  | ssh "$SERVER" "tar xzf - -C $REMOTE_DIR"

# 5. Rättigheter, ev. beroende-synk, och omstart — i ett ssh-anrop.
echo "→ rättigheter + omstart"
ssh "$SERVER" "
  set -e
  chown -R ${SERVICE}:${SERVICE} ${REMOTE_DIR}
  if [ '${SYNC_DEPS}' = '1' ]; then
    cd ${REMOTE_DIR} && /root/.local/bin/uv sync
    chmod -R a+rX /opt/uv
    chown -R ${SERVICE}:${SERVICE} ${REMOTE_DIR}
  fi
  systemctl restart ${SERVICE}
"

# 6. Vänta tills tjänsten faktiskt svarar (uvicorn binder porten strax EFTER att
#    systemd säger 'active' — polla villkoret istället för att gissa en sleep).
echo "→ väntar på att tjänsten svarar"
ssh "$SERVER" "
  for i in 1 2 3 4 5 6 7 8 9 10; do
    curl -fs ${HEALTH_URL} >/dev/null && exit 0
    sleep 1
  done
  echo '✗ tjänsten svarade inte på ${HEALTH_URL} efter omstart' >&2
  exit 1
"

# 7. Rökverifiering: bekräfta att den NYA funktionen nådde prod — inte bara att
#    tjänsten lever. Det här steget är vad som hade fångat 'push ≠ deploy' direkt.
#    >>> Din kontribution nedan. <<<
verify_deploy

echo "✅ Deploy klar och verifierad."
