from app.security import is_allowed, load_allowlist


def test_load_strips_blanks_and_comments(tmp_path):
    f = tmp_path / "allowed_emails.txt"
    f.write_text("# kommentar\nFoo@Example.com\n\n  bar@example.com  \n")
    allowlist = load_allowlist(f)
    assert allowlist == {"foo@example.com", "bar@example.com"}


def test_is_allowed_case_insensitive():
    allowlist = {"foo@example.com"}
    assert is_allowed("FOO@example.com", allowlist) is True


def test_is_allowed_rejects_unknown():
    assert is_allowed("nope@example.com", {"foo@example.com"}) is False


def test_missing_file_is_empty_allowlist(tmp_path):
    assert load_allowlist(tmp_path / "saknas.txt") == set()
