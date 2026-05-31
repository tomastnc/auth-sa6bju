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
