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
