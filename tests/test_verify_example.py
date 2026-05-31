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
    bad_jwks = build_jwks(other.public_key(), compute_kid(other.public_key()))
    try:
        verify_cookie(token, jwks=bad_jwks)
        assert False, "borde avvisa token signerad med annan nyckel"
    except Exception:
        pass
