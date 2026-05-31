# googleauth — Google-inloggning + JWT-cookie för *.sa6bju.se

Tjänst på `auth.sa6bju.se`: logga in med Google, få en EdDSA-signerad JWT i en
cookie för hela `*.sa6bju.se`. Andra subdomän-appar verifierar cookien själva
mot `/.well-known/jwks.json` — ingen central proxy behöver stå framför dem.

## Arkitektur i korthet

```
Browser → app.sa6bju.se (ingen cookie) → redirect → auth.sa6bju.se/login
        → Google → /auth/callback → allowlist-koll → JWT-cookie (.sa6bju.se)
        → tillbaka till appen, som verifierar cookien mot JWKS
```

- **Signering:** Ed25519 (EdDSA). Privat nyckel bara på servern; publik via JWKS.
- **Åtkomst:** allowlist av e-postadresser (`allowed_emails.txt`, bara på servern).
- **Livslängd:** tokens har **inget utgångsdatum** (se Återkallning nedan).

## Endpoints

| Path | Funktion |
|------|----------|
| `GET /login?next=<url>` | Validerar att `next` är `*.sa6bju.se`, startar Google-flödet |
| `GET /auth/callback` | Googles redirect-mål: allowlist-koll, mint, sätter cookie |
| `GET /.well-known/jwks.json` | Publika nyckeln/-arna (appar hämtar + cachar denna) |
| `GET /me` | JSON med inloggad identitet (felsökning) |
| `GET /logout?next=<url>` | Rensar cookien, redirectar |
| `GET /healthz` | Hälsokontroll |

## Lokal utveckling

```bash
uv run pytest -v                 # kör testsviten
uv run python deploy/gen_keys.py ./dev-key.pem
cp .env.example .env             # fyll i, peka JWT_PRIVATE_KEY_PATH=./dev-key.pem
uv run uvicorn app.main:app --reload --port 8081
```

## Driftsättning (på caddy.sa6bju.se)

1. **DNS:** CNAME `auth` → `v5` (Glesys-panelen; ange bara `auth`, inte FQDN).
2. **Google Cloud Console:** skapa OAuth-klient (Web). Authorized redirect URI:
   `https://auth.sa6bju.se/auth/callback`. Authorized domain: `sa6bju.se`.
3. **Kod + nyckel:**
   ```bash
   useradd -r -s /usr/sbin/nologin googleauth
   mkdir -p /opt/googleauth /etc/googleauth
   # kopiera repot till /opt/googleauth
   uv run python deploy/gen_keys.py /etc/googleauth/jwt-private.pem
   chown -R googleauth:googleauth /opt/googleauth /etc/googleauth
   ```
4. **.env** i `/opt/googleauth/.env` (mode 600): client id/secret, `SESSION_SECRET`
   (`openssl rand -hex 32`), `JWT_PRIVATE_KEY_PATH=/etc/googleauth/jwt-private.pem`,
   `ALLOWED_EMAILS_PATH=/etc/googleauth/allowed_emails.txt`.
5. **allowed_emails.txt** i `/etc/googleauth/` — en e-post per rad.
6. **Beroenden:** sätt `UV_PYTHON_INSTALL_DIR=/opt/uv/python` (delad, världsläsbar plats —
   annars hamnar den uv-hämtade Pythonen under `/root` och tjänsteanvändaren `googleauth`
   kan inte nå den → `203/EXEC`). Persistera i `/etc/environment`. Kör sedan `uv sync` i
   `/opt/googleauth` (skapar `.venv` som systemd-enheten startar), `chmod -R a+rX /opt/uv`.
7. **systemd:** `cp deploy/googleauth.service /etc/systemd/system/ && systemctl enable --now googleauth`.
8. **Caddy:** `cp deploy/auth.conf /etc/caddy/sites/ && caddy validate --config /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile`.

## Hur en app använder inloggningen

1. Saknar appen en giltig `sa6bju_session`-cookie → redirecta webbläsaren till
   `https://auth.sa6bju.se/login?next=<appens-url>`.
2. Efter login är användaren tillbaka med cookien satt.
3. Verifiera cookien serverside — se `verify_example.py` (`verify_cookie`). Cookien
   är `HttpOnly`, så den läses ur `Cookie`-headern på servern, inte i webbläsar-JS.

## Återkallning (viktigt)

Tokens har **inget utgångsdatum**. För att ogiltigförklara alla utfärdade tokens
(t.ex. när någon tas bort ur allowlisten och du vill att deras *befintliga* token
ska sluta gälla): generera ett nytt nyckelpar, ersätt `jwt-private.pem`, starta om
tjänsten. Alla måste då logga in på nytt — godkända släpps in igen, borttagna nekas.
Det finns ingen individuell återkallning.

## Förtroendemodell (delad cookie)

Cookien gäller hela `.sa6bju.se`, så alla subdomäner får den. Den är `HttpOnly`
(kan inte läsas av webbläsar-JS), men modellen förutsätter att **all kod som körs
på en sa6bju.se-subdomän är betrodd** — en komprometterad subdomän kan skicka med
cookien mot andra subdomäner. Hosta inte opålitligt/användarkontrollerat innehåll
på en subdomän som delar denna cookie.

> Obs: att bara ta bort någon ur `allowed_emails.txt` stoppar *nya* inloggningar
> direkt (listan läses per request), men påverkar inte en token de redan har. För
> att stänga ute en redan inloggad krävs nyckelrotation enligt ovan.
