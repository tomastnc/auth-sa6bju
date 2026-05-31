# Google-inloggning + domänövergripande JWT-cookie för *.sa6bju.se

> **Status:** Design godkänd-pending — skriven 2026-05-31

## Mål

En central inloggningstjänst på `auth.sa6bju.se` där användare loggar in med sitt
Google-konto. Efter lyckad inloggning sätts en cookie som gäller för hela
`*.sa6bju.se`. Appar på andra subdomäner ska **själva kunna fastställa att cookien
är äkta** och läsa ut vilket Google-konto den tillhör — utan att fråga någon central
proxy.

## Beslutade designval

| Fråga | Val |
|-------|-----|
| Verifieringsmodell | **Självverifierande signerad JWT i cookien** (inte proxy-injicerade headers) |
| Signering | **Asymmetrisk EdDSA (Ed25519)** — privat nyckel på auth-servern, publik via JWKS |
| Åtkomst | **Allowlist av specifika e-postadresser** |
| Stack | **Liten egen FastAPI-tjänst, körd via `uv`** |
| Drift | **Backend bakom befintlig Caddy** på `caddy.sa6bju.se`, lyssnar `127.0.0.1:8081` |
| Token-livslängd | **Obegränsad** (inget `exp`-claim); beständig cookie |
| Versionshantering | **git** i `/home/tomas/infra/googleauth/` |
| allowed_emails.txt | **Bara på servern** (gitignorad; `.example` i repot) |

## Arkitektur

```
Internet → Unifi Gateway → Caddy (caddy.sa6bju.se, TLS) → FastAPI (127.0.0.1:8081)
                                                              ↕ OAuth2
                                                            Google
```

| Komponent | Roll |
|-----------|------|
| **auth.sa6bju.se** (FastAPI/uv) | OAuth2 mot Google, allowlist-koll, mintar JWT, sätter cookie, serverar JWKS |
| **Caddy** | TLS-terminering, proxar `auth.sa6bju.se` → `127.0.0.1:8081`, säkerhetsheaders |
| **Ed25519-nyckelpar** | Privat nyckel signerar (mode 600, ej i git). Publik nyckel via JWKS |
| **Downstream-appar** | Läser cookien, hämtar+cachar JWKS, verifierar signatur + `iss`/`aud`, litar på `email` |

## Inloggningsflöde

```
1. Browser → app.sa6bju.se        (ingen/ogiltig cookie)
2. App redirectar → auth.sa6bju.se/login?next=https://app.sa6bju.se/...
3. /login: validerar att next är *.sa6bju.se, sätter signerad host-only
           state-cookie (kortlivad), redirectar → Google consent
4. Google → auth.sa6bju.se/auth/callback?code=...&state=...
5. callback: matchar state, växlar code → Googles ID-token, läser verifierad email
6. Allowlist-koll: ej i listan → 403. I listan → fortsätt
7. Mintar EdDSA-JWT, Set-Cookie:
       sa6bju_session=<jwt>; Domain=.sa6bju.se; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=<lång>
8. Redirectar tillbaka → next
9. App läser cookien, verifierar mot JWKS, känner användaren
```

State-cookien gör tjänsten **stateless** (ingen server-side sessionslagring) och
skyddar OAuth-flödet mot CSRF samtidigt som den bär `next`-målet.

## JWT-innehåll

| Claim | Värde | Syfte |
|-------|-------|-------|
| `iss` | `https://auth.sa6bju.se` | Vem utfärdade (appar kontrollerar) |
| `sub` | Googles stabila användar-id | Stabil identitet |
| `email` | Verifierad e-post | Primär identitet för appar |
| `email_verified` | `true` | — |
| `name` | Visningsnamn | Bekvämlighet |
| `aud` | `sa6bju.se` | Appar kontrollerar avsedd mottagare |
| `iat` | Utfärdandetid | Behålls trots obegränsad livslängd → möjliggör framtida "äldre än X gäller inte" |
| header `kid` | Nyckel-id | Möjliggör nyckelrotation utan att gamla tokens slutar verifiera |
| header `alg` | `EdDSA` | Signaturalgoritm |

**Inget `exp`-claim** — tokens gäller tills vidare. Avsiktligt: tjänsten används bara
av betrodda personer på betrodda enheter. Cookies kan inte vara tekniskt eviga, så
`Max-Age` sätts mycket långt (≈10 år, `315360000` s) → i praktiken beständig tills
användaren loggar ut eller nyckeln roteras.

### Återkallning (viktig konsekvens av obegränsad livslängd)

Stateless JWT utan `exp` kan **inte återkallas individuellt**. Allowlisten kollas bara
vid inloggning. Enda spärren är **nyckelrotation**: byt Ed25519-nyckelparet →
alla gamla tokens slutar verifiera → alla godkända loggar in på nytt, borttagna
nekas. Dokumenteras i README som "kicka alla"-hävstången.

**Signaturval:** EdDSA primärt (modernt, små nycklar, välstött i Python). RS256 är det
universellt mest kompatibla alternativet; koden är nästan identisk, så bytet
dokumenteras i README ifall en downstream-app i annat språk saknar OKP-stöd.

## Endpoints

| Metod & path | Funktion |
|--------------|----------|
| `GET /login?next=<url>` | Validerar `next` (måste `*.sa6bju.se`), sätter state-cookie, redirect → Google |
| `GET /auth/callback` | Googles redirect-mål. State-match, code-växling, allowlist, mint, set-cookie, redirect → next |
| `GET /.well-known/jwks.json` | Publika nyckeln/-arna (JWKS, `kid`). Cachebar |
| `GET /logout?next=<url>` | Rensar cookien (utgången, `Domain=.sa6bju.se`), redirect |
| `GET /me` | JSON med inloggad identitet (felsökning) |
| `GET /healthz` | Hälsokontroll |

Googles **Authorized redirect URI**: `https://auth.sa6bju.se/auth/callback` (exakt).

## Säkerhet

- Cookie-flaggor: `Domain=.sa6bju.se; Secure; HttpOnly; SameSite=Lax; Path=/`.
  `Lax` tillåter cookien vid top-level-navigering mellan subdomäner men blockerar
  cross-site POST.
- State-cookie + strikt `next`-allowlist (`*.sa6bju.se`) mot CSRF och open redirect.
- Standard sa6bju-säkerhetsheaders (HSTS, nosniff, X-Frame-Options, Referrer-Policy,
  `-Server`) sätts i Caddy.
- Hemligheter (Google client secret, privat nyckel) i `.env` / filer mode 600,
  **aldrig i git**. `.gitignore` + `.env.example`.
- Tjänsten lyssnar bara på `127.0.0.1` — nås aldrig direkt utifrån.

## Filstruktur (`/home/tomas/infra/googleauth/`)

```
googleauth/
├── pyproject.toml          # uv-projekt + beroenden (fastapi, uvicorn, authlib, pyjwt[crypto], cryptography, httpx)
├── app/
│   ├── main.py             # FastAPI-app, endpoints
│   ├── config.py           # env: client id/secret, nyckelväg, allowlist-väg, cookie-domän
│   ├── tokens.py           # minta JWT + bygga JWKS ur Ed25519-nyckel
│   ├── google_oauth.py     # Authlib-klient mot Google
│   └── security.py         # next-validering + allowlist-koll
├── verify_example.py       # fristående exempel: hur en downstream-app verifierar cookien
├── .env.example
├── allowed_emails.txt.example
├── .gitignore              # .env, *.pem/privat nyckel, allowed_emails.txt
├── deploy/
│   ├── auth.conf           # Caddy-site för auth.sa6bju.se
│   ├── googleauth.service  # systemd-enhet
│   └── gen_keys.py         # genererar Ed25519-nyckelpar
├── tests/                  # allowlist, next-validering, JWT-roundtrip, JWKS, tamper, fel iss/aud
└── README.md               # uppsättning, Google Console, nyckelrotation, hur appar integrerar
```

`verify_example.py` är en konkret leverans för det tredje kravet: en kopierbar mall
som andra subdomäner använder för att verifiera cookien och läsa `email`.

## Deployment

1. DNS: CNAME `auth` → `v5` (Glesys-panelen; bara hostname `auth`).
2. Google Cloud Console: OAuth-klient (Web), redirect URI `https://auth.sa6bju.se/auth/callback`.
3. Generera Ed25519-nyckelpar på servern (`gen_keys.py`), privat nyckel mode 600.
4. Lägg `.env` + `allowed_emails.txt` på servern.
5. systemd-tjänst kör uvicorn via `uv` på `127.0.0.1:8081`.
6. Caddy: `sites/auth.conf` proxar `auth.sa6bju.se` → `127.0.0.1:8081`; `caddy validate` + `caddy reload`.

## Testning (TDD)

Enhetstester:
- allowlist-koll (i listan / ej i listan / skiftläge)
- `next`-validering (giltig `*.sa6bju.se`, avvisa extern domän, avvisa schema-trick)
- JWT mint → verify-runda (rätt claims, rätt `kid`)
- JWKS-korrekthet (publik nyckel matchar privat)
- avvisad manipulerad signatur
- avvisat fel `iss` / `aud`

Integration: mockad Google-token-endpoint (callback-flödet utan riktig Google).

## Öppna punkter (medvetet utelämnat ur v1 — YAGNI)

- Token-refresh utan ombounce till Google.
- Individuell återkallning (kräver state/denylist) — accepterat bort pga obegränsad livslängd.
- Grupper/roller i token (`picture`, group-claims) — kan läggas till senare.
