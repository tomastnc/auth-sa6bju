# DEPLOY.md — driftlayout och runbook

Hur den här tjänsten är driftsatt på **`caddy.sa6bju.se`** och hur man sköter den.
För förstagångsuppsättning (Google Console, DNS, nyckelgenerering), se `README.md`.

## Filer på servern

Koden och hemligheterna är medvetet åtskilda: `/opt` är en utbytbar git-checkout,
`/etc/googleauth` håller det oersättliga (signeringsnyckeln) som aldrig rörs vid deploy.

| Plats | Innehåll |
|-------|----------|
| `/opt/googleauth/` | Appkoden (`app/`, `deploy/`, `verify_example.py`, `pyproject.toml`, `.venv/`). Speglar git-repot. |
| `/opt/googleauth/.env` | Google client id/secret, session-secret, sökvägar. Mode 600, ägare `googleauth`. **Ej i git.** |
| `/etc/googleauth/jwt-private.pem` | Ed25519-signeringsnyckeln. Mode 600, ägare `googleauth`. **Oersättlig — rör aldrig vid deploy.** |
| `/etc/googleauth/allowed_emails.txt` | Allowlist, en e-post per rad. Mode 640. Läses per request. |
| `/etc/systemd/system/googleauth.service` | systemd-enhet, kör `uvicorn` på `127.0.0.1:8081` som användaren `googleauth`. |
| `/etc/caddy/sites/auth.conf` | Caddy-site för `auth.sa6bju.se` (TLS + reverse_proxy → 8081). |
| `/opt/uv/python/` | Delad uv-hanterad Python. `.venv` symlänkar hit (se uv-gotcha nedan). |

Körs som tjänsteanvändaren **`googleauth`** (oprivilegierad, `nologin`). All access via
`ssh root@caddy.sa6bju.se`.

## Daglig drift

```bash
# Status och loggar
systemctl status googleauth
journalctl -u googleauth -f
journalctl -u googleauth --since "1h ago"

# Starta om (efter t.ex. kodändring)
systemctl restart googleauth

# Snabb hälsokoll (lokalt på servern)
curl -s http://127.0.0.1:8081/healthz        # {"status":"ok"}
curl -s http://127.0.0.1:8081/.well-known/jwks.json
```

## Hantera allowlist

Läses per request → ändringar slår igenom direkt, ingen omstart behövs.

```bash
nano /etc/googleauth/allowed_emails.txt   # en e-post per rad, # = kommentar
```

- Lägga till någon → de kan logga in direkt vid nästa försök.
- Ta bort någon → stoppar *nya* inloggningar direkt, men deras redan utfärdade
  token lever vidare tills nyckelrotation (se nedan). Det är den medvetna designen.

## Uppdatera koden (deploy)

Koden kopieras från arbetsmaskinen (servern har inte git-remote mot GitHub).

```bash
# Från /home/tomas/infra/googleauth på arbetsmaskinen:
tar czf - --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude=docs . \
  | ssh root@caddy.sa6bju.se 'tar xzf - -C /opt/googleauth'

# På servern, om beroenden ändrats (pyproject.toml/uv.lock):
ssh root@caddy.sa6bju.se '
  cd /opt/googleauth && /root/.local/bin/uv sync
  chmod -R a+rX /opt/uv
  chown -R googleauth:googleauth /opt/googleauth
  systemctl restart googleauth
'
# Vid bara kodändring räcker: systemctl restart googleauth
```

`UV_PYTHON_INSTALL_DIR=/opt/uv/python` ligger i `/etc/environment` så `uv sync`
bygger `.venv` mot den delade Pythonen, inte en under `/root`.

## Återkallning / nyckelrotation

Tokens har **inget utgångsdatum**. Enda sättet att ogiltigförklara alla utfärdade
tokens (t.ex. efter att ha tagit bort någon ur allowlisten):

```bash
ssh root@caddy.sa6bju.se '
  rm /etc/googleauth/jwt-private.pem
  /opt/googleauth/.venv/bin/python /opt/googleauth/deploy/gen_keys.py /etc/googleauth/jwt-private.pem
  chown googleauth:googleauth /etc/googleauth/jwt-private.pem
  chmod 600 /etc/googleauth/jwt-private.pem
  systemctl restart googleauth
'
```

Alla måste då logga in på nytt; godkända släpps in igen, borttagna nekas. Det nya
`kid` exponeras automatiskt via JWKS, så downstream-appar börjar verifiera mot den
nya nyckeln vid nästa hämtning.

## Caddy

```bash
# Efter ändring i auth.conf — validera ALLTID före reload (annars kan alla sites falla)
cp /opt/googleauth/deploy/auth.conf /etc/caddy/sites/auth.conf
caddy validate --config /etc/caddy/Caddyfile
caddy reload --config /etc/caddy/Caddyfile
```

## Felsökning

| Symptom | Trolig orsak |
|---------|--------------|
| `systemctl` → `203/EXEC` | `.venv`-python symlänkar in i `/root` (0700). Sätt `UV_PYTHON_INSTALL_DIR=/opt/uv/python`, kör om `uv sync`, `chmod -R a+rX /opt/uv`. |
| `502` externt | Tjänsten nere → `systemctl status googleauth`, `journalctl -u googleauth`. |
| `{"detail":"Åtkomst nekad"}` (403) | Det inloggade Google-kontot finns inte i `allowed_emails.txt`. |
| `404` på `/` | Förväntat — ingen rotrutt. Använd `/login?next=…`, `/me`, `/healthz`. |
| "Ingen kontakt" / hittar inte servern | Klient-DNS-cache (negativ-TTL upp till 3h efter att posten skapades). Spola DNS eller testa från annat nät. |
| Tjänsten startar men login 500:ar | Felaktiga/saknade Google-creds i `.env`. Vid felkonfig loggar appen `VARNING: ...` till stderr (`journalctl`). |
