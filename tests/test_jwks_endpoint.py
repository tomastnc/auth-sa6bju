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
    jwt.PyJWK.from_dict(jwks["keys"][0])  # kastar om JWK:n är trasig
