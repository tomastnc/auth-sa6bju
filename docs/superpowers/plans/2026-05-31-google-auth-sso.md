# Google-inloggning + JWT-cookie för *.sa6bju.se — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** En FastAPI-tjänst på `auth.sa6bju.se` som loggar in via Google, kontrollerar en e-post-allowlist och sätter en EdDSA-signerad JWT i en cookie för `*.sa6bju.se` som vilken subdomän-app som helst kan verifiera själv via en JWKS-endpoint.

**Architecture:** Stateless tjänst bakom befintliga Caddy (TLS) på `caddy.sa6bju.se`, lyssnar `127.0.0.1:8081`. Google-OAuth via Authlib; transient OAuth-state lagras i en signerad host-only session-cookie (Starlette `SessionMiddleware`). Efter login mintas en JWT (inget `exp`) som läggs i en `Domain=.sa6bju.se`-cookie. Publik nyckel publiceras via `/.well-known/jwks.json`.

**Tech Stack:** Python 3.14, `uv`, FastAPI, uvicorn, Authlib (Starlette-integration), PyJWT[crypto], cryptography, pydantic-settings, pytest + httpx (TestClient).

> **Learning-mode-noteringar:** Tre funktioner är markerade `← DIN KOD` (next-validering, allowlist-koll, claim-bygget). Vid exekvering bjuds du in att skriva dem själv först; referenslösningen nedan finns som facit. Allt annat är infrastruktur.

---

## Filstruktur

| Fil | Ansvar |
|-----|--------|
| `pyproject.toml` | uv-projekt + beroenden |
| `app/__init__.py` | tom paketmarkör |
| `app/config.py` | läser env → `Settings` (client id/secret, nyckelväg, allowlist-väg, cookie-domän, secrets) |
| `app/security.py` | `validate_next`, `load_allowlist`, `is_allowed` |
| `app/tokens.py` | `load_private_key`, `compute_kid`, `mint_session_token`, `build_jwks` |
| `app/google_oauth.py` | Authlib-OAuth-registret konfigurerat mot Google |
| `app/main.py` | FastAPI-app + endpoints (`/login`, `/auth/callback`, `/logout`, `/me`, `/.well-known/jwks.json`, `/healthz`) |
| `verify_example.py` | fristående referens: hur en downstream-app verifierar cookien |
| `deploy/gen_keys.py` | genererar Ed25519-nyckelpar (PEM) |
| `deploy/auth.conf` | Caddy-site |
| `deploy/googleauth.service` | systemd-enhet |
| `.env.example`, `allowed_emails.txt.example`, `README.md` | konfig-mallar + dokumentation |
| `tests/` | enhets- och integrationstester |

---

## Task 1: Projektscaffold + healthz

**Files:**
- Create: `pyproject.toml`
- Create: `app/__init__.py`
- Create: `app/main.py`
- Create: `tests/__init__.py`
- Test: `tests/test_health.py`

- [ ] **Step 1: Skapa `pyproject.toml`**

```toml
[project]
name = "googleauth"
version = "0.1.0"
description = "Google login + JWT cookie for *.sa6bju.se"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.32",
    "authlib>=1.3",
    "pyjwt[crypto]>=2.8",
    "cryptography>=43",
    "pydantic-settings>=2.4",
    "itsdangerous>=2.2",
    "httpx>=0.27",
]

[dependency-groups]
dev = [
    "pytest>=8.3",
]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

- [ ] **Step 2: Skapa paketfiler**

`app/__init__.py` och `tests/__init__.py` — tomma filer.

- [ ] **Step 3: Skriv det felande testet**

`tests/test_health.py`:

```python
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthz_returns_ok():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

- [ ] **Step 4: Kör testet, verifiera att det failar**

Run: `uv run pytest tests/test_health.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.main'` (eller import-fel).

- [ ] **Step 5: Skapa minimal `app/main.py`**

```python
from fastapi import FastAPI

app = FastAPI(title="sa6bju googleauth")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
```

- [ ] **Step 6: Kör testet, verifiera PASS**

Run: `uv run pytest tests/test_health.py -v`
Expected: PASS (uv installerar beroenden automatiskt vid första körningen).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml app/ tests/
git commit -m "Projektscaffold: FastAPI-app med /healthz"
```

---

## Task 2: Ed25519-nyckelgenerering

**Files:**
- Create: `deploy/gen_keys.py`
- Test: `tests/test_keys.py`

- [ ] **Step 1: Skriv det felande testet**

`tests/test_keys.py`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from deploy.gen_keys import generate_private_key_pem


def test_generate_pem_is_loadable_ed25519():
    pem = generate_private_key_pem()
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)


def test_generate_produces_distinct_keys():
    assert generate_private_key_pem() != generate_private_key_pem()
```

- [ ] **Step 2: Kör testet, verifiera FAIL**

Run: `uv run pytest tests/test_keys.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'deploy.gen_keys'`.

- [ ] **Step 3: Skapa `deploy/__init__.py`** (tom) och `deploy/gen_keys.py`

```python
"""Genererar ett Ed25519-nyckelpar för JWT-signering.

Körs på servern: `uv run python deploy/gen_keys.py /etc/googleauth/jwt-private.pem`
Den privata nyckeln lämnar aldrig servern och får mode 600.
"""
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_private_key_pem() -> bytes:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python deploy/gen_keys.py <output-path>", file=sys.stderr)
        raise SystemExit(2)
    out = Path(sys.argv[1])
    out.write_bytes(generate_private_key_pem())
    out.chmod(0o600)
    print(f"Privat nyckel skriven till {out} (mode 600)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Kör testet, verifiera PASS**

Run: `uv run pytest tests/test_keys.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/__init__.py deploy/gen_keys.py tests/test_keys.py
git commit -m "Ed25519-nyckelgenerering med deterministisk PEM-export"
```

---

## Task 3: `validate_next` — open-redirect-skydd  ← DIN KOD

**Files:**
- Create: `app/security.py`
- Test: `tests/test_security_next.py`

- [ ] **Step 1: Skriv de felande testerna**

`tests/test_security_next.py`:

```python
from app.security import validate_next


def test_accepts_https_subdomain():
    assert validate_next("https://app.sa6bju.se/dashboard") is True


def test_accepts_apex_domain():
    assert validate_next("https://sa6bju.se/") is True


def test_rejects_external_domain():
    assert validate_next("https://evil.com/") is False


def test_rejects_lookalike_suffix():
    assert validate_next("https://app.sa6bju.se.evil.com/") is False


def test_rejects_http_scheme():
    assert validate_next("http://app.sa6bju.se/") is False


def test_rejects_missing_host():
    assert validate_next("/just/a/path") is False


def test_rejects_empty():
    assert validate_next("") is False
```

- [ ] **Step 2: Kör testerna, verifiera FAIL**

Run: `uv run pytest tests/test_security_next.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.security'`.

- [ ] **Step 3: Implementera `validate_next` i `app/security.py`**

```python
"""Säkerhetshjälpare: next-validering och allowlist."""
from urllib.parse import urlparse

ALLOWED_HOST = "sa6bju.se"


def validate_next(next_url: str) -> bool:
    """Sant endast om next_url är en absolut https-URL vars host är
    sa6bju.se eller en subdomän därtill. Skyddar mot open redirect."""
    if not next_url:
        return False
    parsed = urlparse(next_url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return host == ALLOWED_HOST or host.endswith("." + ALLOWED_HOST)
```

- [ ] **Step 4: Kör testerna, verifiera PASS**

Run: `uv run pytest tests/test_security_next.py -v`
Expected: PASS (7 tester).

- [ ] **Step 5: Commit**

```bash
git add app/security.py tests/test_security_next.py
git commit -m "validate_next: open-redirect-skydd för *.sa6bju.se"
```

---

## Task 4: Allowlist — `load_allowlist` + `is_allowed`  ← DIN KOD

**Files:**
- Modify: `app/security.py`
- Test: `tests/test_security_allowlist.py`

- [ ] **Step 1: Skriv de felande testerna**

`tests/test_security_allowlist.py`:

```python
from app.security import is_allowed, load_allowlist


def test_load_strips_blanks_and_comments(tmp_path):
    f = tmp_path / "allowed_emails.txt"
    f.write_text("# kommentar\nFoo@Example.com\n\n  bar@example.com  \n")
    allowlist = load_allowlist(f)
    assert allowlist == {"foo@example.com", "bar@example.com"}


def test_is_allowed_case_insensitive():
    allowlist = {"foo@example.com"}
    assert is_allowed("FOO@example.com", allowlist) is True


def test_is_allowed_rejects_unknown():
    assert is_allowed("nope@example.com", {"foo@example.com"}) is False


def test_missing_file_is_empty_allowlist(tmp_path):
    assert load_allowlist(tmp_path / "saknas.txt") == set()
```

- [ ] **Step 2: Kör testerna, verifiera FAIL**

Run: `uv run pytest tests/test_security_allowlist.py -v`
Expected: FAIL — `ImportError: cannot import name 'is_allowed'`.

- [ ] **Step 3: Lägg till i `app/security.py`**

Lägg till överst:

```python
from pathlib import Path
```

Lägg till i slutet av filen:

```python
def load_allowlist(path: Path) -> set[str]:
    """Läser allowlist-filen: en e-post per rad, '#' = kommentar.
    Saknad fil ger tom mängd (= ingen släpps in)."""
    path = Path(path)
    if not path.exists():
        return set()
    emails = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        emails.add(line.lower())
    return emails


def is_allowed(email: str, allowlist: set[str]) -> bool:
    return email.strip().lower() in allowlist
```

- [ ] **Step 4: Kör testerna, verifiera PASS**

Run: `uv run pytest tests/test_security_allowlist.py -v`
Expected: PASS (4 tester).

- [ ] **Step 5: Commit**

```bash
git add app/security.py tests/test_security_allowlist.py
git commit -m "Allowlist: load_allowlist + is_allowed (case-insensitive)"
```

---

## Task 5: Token-mint + JWKS  ← DIN KOD (claim-bygget)

**Files:**
- Create: `app/tokens.py`
- Test: `tests/test_tokens.py`

- [ ] **Step 1: Skriv de felande testerna**

`tests/test_tokens.py`:

```python
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.tokens import build_jwks, compute_kid, mint_session_token

ISSUER = "https://auth.sa6bju.se"
AUDIENCE = "sa6bju.se"


def _key():
    return Ed25519PrivateKey.generate()


def test_kid_is_stable_for_same_key():
    key = _key()
    assert compute_kid(key.public_key()) == compute_kid(key.public_key())


def test_kid_differs_between_keys():
    assert compute_kid(_key().public_key()) != compute_kid(_key().public_key())


def test_mint_and_verify_roundtrip():
    key = _key()
    kid = compute_kid(key.public_key())
    token = mint_session_token(
        sub="g-123", email="foo@example.com", email_verified=True,
        name="Foo", private_key=key, kid=kid, issuer=ISSUER, audience=AUDIENCE,
    )
    claims = jwt.decode(
        token, key.public_key(), algorithms=["EdDSA"],
        audience=AUDIENCE, issuer=ISSUER,
    )
    assert claims["sub"] == "g-123"
    assert claims["email"] == "foo@example.com"
    assert claims["email_verified"] is True
    assert claims["name"] == "Foo"
    assert "iat" in claims
    assert "exp" not in claims  # obegränsad livslängd


def test_token_header_carries_kid():
    key = _key()
    kid = compute_kid(key.public_key())
    token = mint_session_token(
        sub="g-1", email="a@b.se", email_verified=True, name="A",
        private_key=key, kid=kid, issuer=ISSUER, audience=AUDIENCE,
    )
    assert jwt.get_unverified_header(token)["kid"] == kid


def test_tampered_token_rejected():
    key = _key()
    kid = compute_kid(key.public_key())
    token = mint_session_token(
        sub="g-1", email="a@b.se", email_verified=True, name="A",
        private_key=key, kid=kid, issuer=ISSUER, audience=AUDIENCE,
    )
    body, sig = token.rsplit(".", 1)
    forged = body + "." + ("A" * len(sig))
    try:
        jwt.decode(forged, key.public_key(), algorithms=["EdDSA"],
                   audience=AUDIENCE, issuer=ISSUER)
        assert False, "manipulerad token borde avvisas"
    except jwt.InvalidTokenError:
        pass


def test_jwks_verifies_token():
    key = _key()
    kid = compute_kid(key.public_key())
    jwks = build_jwks(key.public_key(), kid)
    assert jwks["keys"][0]["kid"] == kid
    assert jwks["keys"][0]["kty"] == "OKP"
    token = mint_session_token(
        sub="g-1", email="a@b.se", email_verified=True, name="A",
        private_key=key, kid=kid, issuer=ISSUER, audience=AUDIENCE,
    )
    signing_key = jwt.PyJWK.from_dict(jwks["keys"][0])
    claims = jwt.decode(token, signing_key.key, algorithms=["EdDSA"],
                        audience=AUDIENCE, issuer=ISSUER)
    assert claims["email"] == "a@b.se"
```

- [ ] **Step 2: Kör testerna, verifiera FAIL**

Run: `uv run pytest tests/test_tokens.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.tokens'`.

- [ ] **Step 3: Implementera `app/tokens.py`**

```python
"""Mintar EdDSA-JWT och bygger JWKS ur ett Ed25519-nyckelpar."""
import base64
import hashlib
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jwt.algorithms import OKPAlgorithm


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Förväntade en Ed25519 privat nyckel")
    return key


def compute_kid(public_key: Ed25519PublicKey) -> str:
    """Deterministiskt nyckel-id = base64url(sha256(raw publik nyckel))[:16]."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")[:16]


def mint_session_token(
    *,
    sub: str,
    email: str,
    email_verified: bool,
    name: str,
    private_key: Ed25519PrivateKey,
    kid: str,
    issuer: str,
    audience: str,
) -> str:
    """Bygger claim-uppsättningen och signerar med EdDSA. Inget exp-claim."""
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "email": email,
        "email_verified": email_verified,
        "name": name,
        "iat": int(time.time()),
    }
    return jwt.encode(claims, private_key, algorithm="EdDSA", headers={"kid": kid})


def build_jwks(public_key: Ed25519PublicKey, kid: str) -> dict:
    jwk = OKPAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "EdDSA"})
    return {"keys": [jwk]}
```

- [ ] **Step 4: Kör testerna, verifiera PASS**

Run: `uv run pytest tests/test_tokens.py -v`
Expected: PASS (6 tester).

- [ ] **Step 5: Commit**

```bash
git add app/tokens.py tests/test_tokens.py
git commit -m "Token-mint (EdDSA, inget exp) + JWKS med deterministiskt kid"
```

---

## Task 6: Settings + OAuth-registret

**Files:**
- Create: `app/config.py`
- Create: `app/google_oauth.py`
- Create: `.env.example`
- Test: `tests/test_config.py`

- [ ] **Step 1: Skriv det felande testet**

`tests/test_config.py`:

```python
from app.config import Settings


def test_settings_reads_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SESSION_SECRET", "sess")
    monkeypatch.setenv("JWT_PRIVATE_KEY_PATH", "/tmp/key.pem")
    monkeypatch.setenv("ALLOWED_EMAILS_PATH", "/tmp/allowed.txt")
    s = Settings()
    assert s.google_client_id == "cid"
    assert s.cookie_domain == ".sa6bju.se"           # default
    assert s.issuer == "https://auth.sa6bju.se"      # default
    assert s.audience == "sa6bju.se"                 # default
    assert s.cookie_name == "sa6bju_session"         # default
```

- [ ] **Step 2: Kör testet, verifiera FAIL**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.config'`.

- [ ] **Step 3: Implementera `app/config.py`**

```python
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    google_client_id: str
    google_client_secret: str
    session_secret: str
    jwt_private_key_path: str
    allowed_emails_path: str

    base_url: str = "https://auth.sa6bju.se"
    issuer: str = "https://auth.sa6bju.se"
    audience: str = "sa6bju.se"
    cookie_domain: str = ".sa6bju.se"
    cookie_name: str = "sa6bju_session"
    cookie_max_age: int = 315360000  # ~10 år, i praktiken beständig


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 4: Kör testet, verifiera PASS**

Run: `uv run pytest tests/test_config.py -v`
Expected: PASS.

- [ ] **Step 5: Implementera `app/google_oauth.py`**

```python
"""Authlib-OAuth-registret konfigurerat mot Google (OpenID Connect)."""
from authlib.integrations.starlette_client import OAuth

from app.config import Settings


def build_oauth(settings: Settings) -> OAuth:
    oauth = OAuth()
    oauth.register(
        name="google",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth
```

- [ ] **Step 6: Skapa `.env.example`**

```bash
# Google Cloud Console → OAuth-klient (Web)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# openssl rand -hex 32  — signerar den transienta OAuth-state-cookien
SESSION_SECRET=

# Genereras med deploy/gen_keys.py, mode 600, ALDRIG i git
JWT_PRIVATE_KEY_PATH=/etc/googleauth/jwt-private.pem

# En e-post per rad, ALDRIG i git
ALLOWED_EMAILS_PATH=/etc/googleauth/allowed_emails.txt
```

- [ ] **Step 7: Commit**

```bash
git add app/config.py app/google_oauth.py .env.example tests/test_config.py
git commit -m "Settings (pydantic) + Authlib Google-OAuth-registret + .env.example"
```

---

## Task 7: JWKS-endpoint + app-state-uppkoppling

**Files:**
- Modify: `app/main.py`
- Test: `tests/test_jwks_endpoint.py`

> Denna task kopplar in nyckel, settings och OAuth i appen via en liten
> `build_app(settings)`-fabrik så att testerna kan injicera en temp-nyckel.

- [ ] **Step 1: Skriv det felande testet**

`tests/test_jwks_endpoint.py`:

```python
import jwt
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import build_app
from app.tokens import compute_kid, load_private_key
from deploy.gen_keys import generate_private_key_pem


def _settings(tmp_path):
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(generate_private_key_pem())
    allow = tmp_path / "allow.txt"
    allow.write_text("foo@example.com\n")
    return Settings(
        google_client_id="cid", google_client_secret="sec", session_secret="s",
        jwt_private_key_path=str(key_path), allowed_emails_path=str(allow),
    )


def test_jwks_endpoint_matches_private_key(tmp_path):
    settings = _settings(tmp_path)
    client = TestClient(build_app(settings))
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    jwks = resp.json()
    expected_kid = compute_kid(load_private_key(settings.jwt_private_key_path).public_key())
    assert jwks["keys"][0]["kid"] == expected_kid
    # JWK:n ska kunna verifiera en token signerad med privata nyckeln
    jwt.PyJWK.from_dict(jwks["keys"][0])  # kastar om JWK:n är trasig
```

- [ ] **Step 2: Kör testet, verifiera FAIL**

Run: `uv run pytest tests/test_jwks_endpoint.py -v`
Expected: FAIL — `ImportError: cannot import name 'build_app'`.

- [ ] **Step 3: Skriv om `app/main.py` till en `build_app`-fabrik**

```python
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings, get_settings
from app.google_oauth import build_oauth
from app.security import is_allowed, load_allowlist
from app.tokens import build_jwks, compute_kid, load_private_key


def build_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="sa6bju googleauth")
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        https_only=True,
        same_site="lax",
        # ingen domain → host-only på auth.sa6bju.se
    )

    private_key = load_private_key(settings.jwt_private_key_path)
    public_key = private_key.public_key()
    kid = compute_kid(public_key)
    oauth = build_oauth(settings)

    app.state.settings = settings
    app.state.private_key = private_key
    app.state.kid = kid
    app.state.oauth = oauth

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    def jwks() -> JSONResponse:
        return JSONResponse(build_jwks(public_key, kid))

    return app


def _build_default() -> FastAPI:
    """Modulnivå-app för uvicorn (`app.main:app`). Om env saknas vid t.ex.
    testimport returneras en minimal app istället för att krascha importen —
    testerna använder build_app(settings) direkt med en temp-nyckel."""
    try:
        return build_app(get_settings())
    except Exception:
        return FastAPI(title="sa6bju googleauth (unconfigured)")


app = _build_default()
```

- [ ] **Step 4: Kör testet, verifiera PASS**

Run: `uv run pytest tests/test_jwks_endpoint.py tests/test_health.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/main.py tests/test_jwks_endpoint.py
git commit -m "build_app-fabrik + /.well-known/jwks.json"
```

---

## Task 8: `/login` med next-validering

**Files:**
- Modify: `app/main.py`
- Test: `tests/test_login.py`

- [ ] **Step 1: Skriv de felande testerna**

`tests/test_login.py`:

```python
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

from tests.test_jwks_endpoint import _settings
from app.main import build_app


def test_login_rejects_bad_next(tmp_path):
    client = TestClient(build_app(_settings(tmp_path)))
    resp = client.get("/login?next=https://evil.com/", follow_redirects=False)
    assert resp.status_code == 400


def test_login_redirects_to_google_for_valid_next(tmp_path):
    app = build_app(_settings(tmp_path))
    # mocka Googles authorize_redirect så inget nät behövs
    app.state.oauth.google.authorize_redirect = AsyncMock(
        return_value=RedirectResponse("https://accounts.google.com/o/oauth2/v2/auth?x=1")
    )
    client = TestClient(app)
    resp = client.get(
        "/login?next=https://app.sa6bju.se/dash", follow_redirects=False
    )
    assert resp.status_code in (302, 307)
    assert "accounts.google.com" in resp.headers["location"]
    app.state.oauth.google.authorize_redirect.assert_awaited_once()
```

- [ ] **Step 2: Kör testerna, verifiera FAIL**

Run: `uv run pytest tests/test_login.py -v`
Expected: FAIL — 404 på `/login`.

- [ ] **Step 3: Lägg till `/login` i `build_app` (inuti fabriken, efter jwks)**

```python
    from fastapi import HTTPException, Request

    @app.get("/login")
    async def login(request: Request, next: str = ""):
        from app.security import validate_next

        if not validate_next(next):
            raise HTTPException(status_code=400, detail="Ogiltig next-parameter")
        request.session["next"] = next
        redirect_uri = f"{settings.base_url}/auth/callback"
        return await oauth.google.authorize_redirect(request, redirect_uri)
```

- [ ] **Step 4: Kör testerna, verifiera PASS**

Run: `uv run pytest tests/test_login.py -v`
Expected: PASS (2 tester).

- [ ] **Step 5: Commit**

```bash
git add app/main.py tests/test_login.py
git commit -m "/login: next-validering + redirect till Google"
```

---

## Task 9: `/auth/callback` — exchange, allowlist, mint, set-cookie

**Files:**
- Modify: `app/main.py`
- Test: `tests/test_callback.py`

- [ ] **Step 1: Skriv de felande testerna**

`tests/test_callback.py`:

```python
from unittest.mock import AsyncMock

import jwt
from fastapi.testclient import TestClient

from tests.test_jwks_endpoint import _settings
from app.main import build_app


def _mock_google(app, *, email, verified=True, sub="g-1", name="Foo"):
    app.state.oauth.google.authorize_access_token = AsyncMock(
        return_value={"userinfo": {
            "sub": sub, "email": email, "email_verified": verified, "name": name,
        }}
    )


def test_callback_sets_cookie_for_allowed_user(tmp_path):
    settings = _settings(tmp_path)  # allowlist innehåller foo@example.com
    app = build_app(settings)
    _mock_google(app, email="foo@example.com")
    client = TestClient(app)
    # lägg next i sessionen via direkt cookie-injektion: gå via /login först
    app.state.oauth.google.authorize_redirect = AsyncMock(
        return_value=__import__("starlette.responses", fromlist=["RedirectResponse"]).RedirectResponse("https://accounts.google.com/")
    )
    client.get("/login?next=https://app.sa6bju.se/dash", follow_redirects=False)
    resp = client.get("/auth/callback?code=x&state=y", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "https://app.sa6bju.se/dash"
    set_cookie = resp.headers["set-cookie"]
    assert settings.cookie_name in set_cookie
    assert "Domain=.sa6bju.se" in set_cookie
    assert "HttpOnly" in set_cookie
    # token i cookien ska verifiera och bära rätt email
    token = client.cookies.get(settings.cookie_name)
    claims = jwt.decode(
        token, app.state.private_key.public_key(), algorithms=["EdDSA"],
        audience=settings.audience, issuer=settings.issuer,
    )
    assert claims["email"] == "foo@example.com"


def test_callback_rejects_disallowed_user(tmp_path):
    settings = _settings(tmp_path)
    app = build_app(settings)
    _mock_google(app, email="intruder@example.com")
    client = TestClient(app)
    resp = client.get("/auth/callback?code=x&state=y", follow_redirects=False)
    assert resp.status_code == 403


def test_callback_rejects_unverified_email(tmp_path):
    settings = _settings(tmp_path)
    app = build_app(settings)
    _mock_google(app, email="foo@example.com", verified=False)
    client = TestClient(app)
    resp = client.get("/auth/callback?code=x&state=y", follow_redirects=False)
    assert resp.status_code == 403
```

- [ ] **Step 2: Kör testerna, verifiera FAIL**

Run: `uv run pytest tests/test_callback.py -v`
Expected: FAIL — 404 på `/auth/callback`.

- [ ] **Step 3: Lägg till `/auth/callback` i `build_app`**

```python
    from fastapi.responses import RedirectResponse

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get("userinfo") or {}
        email = (userinfo.get("email") or "").strip()
        verified = bool(userinfo.get("email_verified"))

        allowlist = load_allowlist(settings.allowed_emails_path)
        if not verified or not is_allowed(email, allowlist):
            raise HTTPException(status_code=403, detail="Åtkomst nekad")

        from app.tokens import mint_session_token

        jwt_token = mint_session_token(
            sub=userinfo.get("sub", ""),
            email=email,
            email_verified=verified,
            name=userinfo.get("name", ""),
            private_key=app.state.private_key,
            kid=app.state.kid,
            issuer=settings.issuer,
            audience=settings.audience,
        )
        next_url = request.session.pop("next", settings.base_url)
        response = RedirectResponse(next_url, status_code=302)
        response.set_cookie(
            key=settings.cookie_name,
            value=jwt_token,
            domain=settings.cookie_domain,
            max_age=settings.cookie_max_age,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response
```

- [ ] **Step 4: Kör testerna, verifiera PASS**

Run: `uv run pytest tests/test_callback.py -v`
Expected: PASS (3 tester).

- [ ] **Step 5: Commit**

```bash
git add app/main.py tests/test_callback.py
git commit -m "/auth/callback: allowlist-koll, mint, domänövergripande cookie"
```

---

## Task 10: `/logout` + `/me`

**Files:**
- Modify: `app/main.py`
- Test: `tests/test_logout_me.py`

- [ ] **Step 1: Skriv de felande testerna**

`tests/test_logout_me.py`:

```python
from fastapi.testclient import TestClient

from tests.test_jwks_endpoint import _settings
from app.main import build_app
from app.tokens import compute_kid, load_private_key, mint_session_token


def _make_token(settings):
    key = load_private_key(settings.jwt_private_key_path)
    return mint_session_token(
        sub="g-1", email="foo@example.com", email_verified=True, name="Foo",
        private_key=key, kid=compute_kid(key.public_key()),
        issuer=settings.issuer, audience=settings.audience,
    )


def test_me_returns_identity_when_cookie_valid(tmp_path):
    settings = _settings(tmp_path)
    app = build_app(settings)
    client = TestClient(app)
    client.cookies.set(settings.cookie_name, _make_token(settings))
    resp = client.get("/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == "foo@example.com"


def test_me_401_without_cookie(tmp_path):
    client = TestClient(build_app(_settings(tmp_path)))
    assert client.get("/me").status_code == 401


def test_logout_clears_cookie(tmp_path):
    settings = _settings(tmp_path)
    client = TestClient(build_app(settings))
    resp = client.get(
        "/logout?next=https://app.sa6bju.se/", follow_redirects=False
    )
    assert resp.status_code in (302, 307)
    set_cookie = resp.headers["set-cookie"]
    assert settings.cookie_name in set_cookie
    assert "Domain=.sa6bju.se" in set_cookie
    assert ("Max-Age=0" in set_cookie) or ("expires=" in set_cookie.lower())
```

- [ ] **Step 2: Kör testerna, verifiera FAIL**

Run: `uv run pytest tests/test_logout_me.py -v`
Expected: FAIL — 404 på `/me`.

- [ ] **Step 3: Lägg till `/me` och `/logout` i `build_app`**

```python
    import jwt as _jwt

    @app.get("/me")
    def me(request: Request):
        token = request.cookies.get(settings.cookie_name)
        if not token:
            raise HTTPException(status_code=401, detail="Ingen session")
        try:
            claims = _jwt.decode(
                token, public_key, algorithms=["EdDSA"],
                audience=settings.audience, issuer=settings.issuer,
            )
        except _jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Ogiltig token")
        return {"email": claims["email"], "name": claims.get("name"), "sub": claims["sub"]}

    @app.get("/logout")
    def logout(next: str = ""):
        from app.security import validate_next

        target = next if validate_next(next) else settings.base_url
        response = RedirectResponse(target, status_code=302)
        response.delete_cookie(
            key=settings.cookie_name, domain=settings.cookie_domain, path="/"
        )
        return response
```

- [ ] **Step 4: Kör hela sviten, verifiera PASS**

Run: `uv run pytest -v`
Expected: PASS (alla tester).

- [ ] **Step 5: Commit**

```bash
git add app/main.py tests/test_logout_me.py
git commit -m "/me (verifierar cookie) + /logout (rensar domäncookie)"
```

---

## Task 11: Downstream-verifieringsexempel

**Files:**
- Create: `verify_example.py`
- Test: `tests/test_verify_example.py`

> Konkret leverans för kravet "appar ska kunna fastställa att cookien är äkta".
> `verify_cookie` tar en JWKS-dict (injicerbar) så den testas offline; docstring
> visar hur man i produktion hämtar JWKS via `jwt.PyJWKClient(url)`.

- [ ] **Step 1: Skriv det felande testet**

`tests/test_verify_example.py`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.tokens import build_jwks, compute_kid, mint_session_token
from verify_example import verify_cookie

ISSUER = "https://auth.sa6bju.se"
AUDIENCE = "sa6bju.se"


def test_verify_cookie_accepts_genuine_token():
    key = Ed25519PrivateKey.generate()
    kid = compute_kid(key.public_key())
    jwks = build_jwks(key.public_key(), kid)
    token = mint_session_token(
        sub="g-1", email="foo@example.com", email_verified=True, name="Foo",
        private_key=key, kid=kid, issuer=ISSUER, audience=AUDIENCE,
    )
    claims = verify_cookie(token, jwks=jwks)
    assert claims["email"] == "foo@example.com"


def test_verify_cookie_rejects_wrong_key():
    good = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    kid = compute_kid(good.public_key())
    token = mint_session_token(
        sub="g-1", email="foo@example.com", email_verified=True, name="Foo",
        private_key=good, kid=kid, issuer=ISSUER, audience=AUDIENCE,
    )
    # JWKS från en annan nyckel → verifiering ska misslyckas
    bad_jwks = build_jwks(other.public_key(), compute_kid(other.public_key()))
    try:
        verify_cookie(token, jwks=bad_jwks)
        assert False, "borde avvisa token signerad med annan nyckel"
    except Exception:
        pass
```

- [ ] **Step 2: Kör testet, verifiera FAIL**

Run: `uv run pytest tests/test_verify_example.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'verify_example'`.

- [ ] **Step 3: Implementera `verify_example.py`**

```python
"""Referensexempel: hur en app på en annan *.sa6bju.se-subdomän verifierar
sessionscookien och läser ut vilket Google-konto den tillhör.

Kopiera in i din app. I produktion: hämta och cacha JWKS automatiskt med
`jwt.PyJWKClient` istället för att skicka in en jwks-dict:

    jwks_client = jwt.PyJWKClient("https://auth.sa6bju.se/.well-known/jwks.json")
    signing_key = jwks_client.get_signing_key_from_jwt(token).key

Cookien heter `sa6bju_session`. Den är HttpOnly → läs den serverside ur
`Cookie`-headern, inte i webbläsar-JS.
"""
import jwt

ISSUER = "https://auth.sa6bju.se"
AUDIENCE = "sa6bju.se"
JWKS_URL = "https://auth.sa6bju.se/.well-known/jwks.json"


def verify_cookie(token: str, *, jwks: dict | None = None) -> dict:
    """Verifierar JWT:n och returnerar dess claims (innehåller 'email', 'sub',
    'name'). Kastar jwt.InvalidTokenError om signatur/iss/aud inte stämmer.

    jwks: skicka in en JWKS-dict i tester; utelämna i produktion → hämtas från
    JWKS_URL och cachas av PyJWKClient.
    """
    header = jwt.get_unverified_header(token)
    if jwks is not None:
        match = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
        signing_key = jwt.PyJWK.from_dict(match).key
    else:
        signing_key = jwt.PyJWKClient(JWKS_URL).get_signing_key_from_jwt(token).key

    return jwt.decode(
        token, signing_key, algorithms=["EdDSA"],
        audience=AUDIENCE, issuer=ISSUER,
    )
```

- [ ] **Step 4: Kör testet, verifiera PASS**

Run: `uv run pytest tests/test_verify_example.py -v`
Expected: PASS (2 tester).

- [ ] **Step 5: Commit**

```bash
git add verify_example.py tests/test_verify_example.py
git commit -m "verify_example: referens för downstream-cookie-verifiering"
```

---

## Task 12: Deploy-artefakter + README

**Files:**
- Create: `deploy/auth.conf`
- Create: `deploy/googleauth.service`
- Create: `allowed_emails.txt.example`
- Create: `README.md`

> Ingen kod att testa — verifieras vid driftsättning (manuell checklista i slutet).

- [ ] **Step 1: Skapa `deploy/auth.conf` (Caddy-site)**

```caddyfile
auth.sa6bju.se {
    reverse_proxy 127.0.0.1:8081

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
}
```

- [ ] **Step 2: Skapa `deploy/googleauth.service` (systemd)**

```ini
[Unit]
Description=sa6bju googleauth (Google login + JWT cookie)
After=network.target

[Service]
Type=simple
User=googleauth
Group=googleauth
WorkingDirectory=/opt/googleauth
EnvironmentFile=/opt/googleauth/.env
ExecStart=/usr/local/bin/uv run uvicorn app.main:app --host 127.0.0.1 --port 8081
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Skapa `allowed_emails.txt.example`**

```text
# En e-post per rad. Rader som börjar med # ignoreras.
# Denna fil är en MALL — den riktiga allowed_emails.txt ligger bara på servern.
din-email@gmail.com
```

- [ ] **Step 4: Skapa `README.md`**

```markdown
# googleauth — Google-inloggning + JWT-cookie för *.sa6bju.se

Tjänst på `auth.sa6bju.se`: logga in med Google, få en EdDSA-signerad JWT i en
cookie för hela `*.sa6bju.se`. Andra subdomän-appar verifierar cookien själva
mot `/.well-known/jwks.json`.

## Lokal utveckling

```bash
uv run pytest -v                 # kör testsviten
uv run python deploy/gen_keys.py ./dev-key.pem
# fyll i .env (kopiera .env.example), peka JWT_PRIVATE_KEY_PATH=./dev-key.pem
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
6. **systemd:** `cp deploy/googleauth.service /etc/systemd/system/ && systemctl enable --now googleauth`.
7. **Caddy:** `cp deploy/auth.conf /etc/caddy/sites/ && caddy validate --config /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile`.

## Hur en app använder inloggningen

1. Saknar appen en giltig `sa6bju_session`-cookie → redirecta webbläsaren till
   `https://auth.sa6bju.se/login?next=<appens-url>`.
2. Efter login är användaren tillbaka med cookien satt.
3. Verifiera cookien serverside — se `verify_example.py` (`verify_cookie`).

## Återkallning (viktigt)

Tokens har **inget utgångsdatum**. För att ogiltigförklara alla utfärdade tokens
(t.ex. när någon tas bort ur allowlisten): generera ett nytt nyckelpar, ersätt
`jwt-private.pem`, starta om tjänsten. Alla måste då logga in på nytt — godkända
släpps in igen, borttagna nekas. Det finns ingen individuell återkallning.
```

- [ ] **Step 5: Commit**

```bash
git add deploy/auth.conf deploy/googleauth.service allowed_emails.txt.example README.md
git commit -m "Deploy-artefakter (Caddy, systemd) + README med drift- och rotationssteg"
```

---

## Manuell driftsverifiering (efter deploy)

1. `curl -s https://auth.sa6bju.se/healthz` → `{"status":"ok"}`
2. `curl -s https://auth.sa6bju.se/.well-known/jwks.json` → JSON med en `OKP`-nyckel
3. Öppna `https://auth.sa6bju.se/login?next=https://app.sa6bju.se/` i webbläsare →
   redirect till Google.
4. Logga in med **godkänt** konto → tillbaka till next, cookie `sa6bju_session` satt
   för `.sa6bju.se`.
5. Logga in med **ej godkänt** konto → 403.
6. `curl` mot en skyddad subdomän med cookien → appen läser rätt `email`.
7. `https://auth.sa6bju.se/logout?next=https://app.sa6bju.se/` → cookie rensad.

---

## Self-review (ifylld)

- **Spec-täckning:** JWT-modell (T5), asymmetrisk EdDSA + JWKS (T5/T7), allowlist
  (T4/T9), FastAPI/uv (T1/T6), obegränsad livslängd utan exp (T5), cookie för
  `.sa6bju.se` (T9), downstream-verifiering (T11), Caddy/systemd-deploy (T12),
  nyckelrotation som återkallning (T12 README). Alla spec-krav har en task.
- **Placeholder-scan:** inga TBD/TODO i kodsteg. (T7 Step 3 påpekar uttryckligen att
  `_env_ready`-raden ska ersättas av `_build_default` — ingen kvarlämnad platshållare.)
- **Typ-konsistens:** `mint_session_token`, `build_jwks`, `compute_kid`,
  `load_private_key`, `validate_next`, `is_allowed`, `load_allowlist`,
  `build_app`, `verify_cookie` används med samma signaturer genomgående.
  Cookie-namnet `sa6bju_session` och claim-namnen (`email`, `sub`, `name`,
  `email_verified`, `iat`, `iss`, `aud`) är enhetliga i alla tasks.
```
