from unittest.mock import AsyncMock

import jwt
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

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
    app.state.oauth.google.authorize_redirect = AsyncMock(
        return_value=RedirectResponse("https://accounts.google.com/")
    )
    # base_url=https krävs för att SessionMiddleware (https_only=True) ska
    # skicka tillbaka Secure-cookien på efterföljande anrop.
    client = TestClient(app, base_url="https://testserver")
    # lägg next i sessionen via /login först
    client.get("/login?next=https://app.sa6bju.se/dash", follow_redirects=False)
    resp = client.get("/auth/callback?code=x&state=y", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "https://app.sa6bju.se/dash"
    set_cookie = resp.headers["set-cookie"]
    assert settings.cookie_name in set_cookie
    assert "Domain=.sa6bju.se" in set_cookie
    assert "HttpOnly" in set_cookie
    # httpx lagrar inte cookies med Domain=.sa6bju.se för testserver —
    # extrahera token direkt från Set-Cookie-headern.
    token = set_cookie.split(";")[0].split("=", 1)[1]
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


def test_callback_rejects_missing_sub(tmp_path):
    settings = _settings(tmp_path)
    app = build_app(settings)
    _mock_google(app, email="foo@example.com", sub="")
    client = TestClient(app)
    resp = client.get("/auth/callback?code=x&state=y", follow_redirects=False)
    assert resp.status_code == 403


def test_callback_without_next_falls_back_to_base_url(tmp_path):
    settings = _settings(tmp_path)
    app = build_app(settings)
    _mock_google(app, email="foo@example.com")
    client = TestClient(app, base_url="https://testserver")
    # gå INTE via /login först → ingen next i sessionen
    resp = client.get("/auth/callback?code=x&state=y", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == settings.base_url
