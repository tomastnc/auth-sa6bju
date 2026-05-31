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
