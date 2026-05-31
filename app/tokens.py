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
    try:
        jwk = OKPAlgorithm.to_jwk(public_key, as_dict=True)
    except TypeError:
        import json
        jwk = json.loads(OKPAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "EdDSA"})
    return {"keys": [jwk]}
