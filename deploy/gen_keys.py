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
    if out.exists():
        print(
            f"Fel: {out} finns redan. Ta bort filen manuellt för att rotera nyckeln.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    out.write_bytes(generate_private_key_pem())
    out.chmod(0o600)
    print(f"Privat nyckel skriven till {out} (mode 600)")


if __name__ == "__main__":
    main()
