import jwt
import pytest
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
    # Annat kid → uppslaget i JWKS misslyckas redan innan jwt.decode.
    with pytest.raises(Exception):
        verify_cookie(token, jwks=bad_jwks)


def test_verify_cookie_rejects_forged_signature_with_matching_kid():
    """En token signerad med fel nyckel men som bär rätt kid: uppslaget i JWKS
    lyckas, så avvisningen måste ske på själva signaturen i jwt.decode."""
    real = Ed25519PrivateKey.generate()
    forger = Ed25519PrivateKey.generate()
    kid = compute_kid(real.public_key())  # det äkta kid:t
    # signerad av angriparens nyckel men med det ÄKTA kid:t i headern
    forged = mint_session_token(
        sub="g-1", email="foo@example.com", email_verified=True, name="Foo",
        private_key=forger, kid=kid, issuer=ISSUER, audience=AUDIENCE,
    )
    jwks = build_jwks(real.public_key(), kid)  # JWKS har den äkta nyckeln under kid
    with pytest.raises(jwt.InvalidSignatureError):
        verify_cookie(forged, jwks=jwks)
