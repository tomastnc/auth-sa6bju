from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from deploy.gen_keys import generate_private_key_pem


def test_generate_pem_is_loadable_ed25519():
    pem = generate_private_key_pem()
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)


def test_generate_produces_distinct_keys():
    assert generate_private_key_pem() != generate_private_key_pem()
