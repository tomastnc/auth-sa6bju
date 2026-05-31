import sys
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from deploy.gen_keys import generate_private_key_pem, main


def test_generate_pem_is_loadable_ed25519():
    pem = generate_private_key_pem()
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)


def test_generate_produces_distinct_keys():
    assert generate_private_key_pem() != generate_private_key_pem()


def test_main_refuses_to_overwrite_existing_file(tmp_path, monkeypatch):
    target = tmp_path / "key.pem"
    target.write_text("existing")
    monkeypatch.setattr(sys, "argv", ["gen_keys.py", str(target)])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert target.read_text() == "existing"  # untouched


def test_main_writes_key_when_file_does_not_exist(tmp_path, monkeypatch):
    target = tmp_path / "key.pem"
    monkeypatch.setattr(sys, "argv", ["gen_keys.py", str(target)])
    main()
    assert target.exists()
    # Verify it is a valid Ed25519 PEM key
    key = serialization.load_pem_private_key(target.read_bytes(), password=None)
    assert isinstance(key, Ed25519PrivateKey)
    # Verify mode 0o600
    file_mode = stat.S_IMODE(target.stat().st_mode)
    assert file_mode == 0o600
