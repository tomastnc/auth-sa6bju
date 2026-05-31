from app.security import validate_next


def test_accepts_https_subdomain():
    assert validate_next("https://app.sa6bju.se/dashboard") is True


def test_accepts_apex_domain():
    assert validate_next("https://sa6bju.se/") is True


def test_rejects_external_domain():
    assert validate_next("https://evil.com/") is False


def test_rejects_lookalike_suffix():
    assert validate_next("https://app.sa6bju.se.evil.com/") is False


def test_rejects_http_scheme():
    assert validate_next("http://app.sa6bju.se/") is False


def test_rejects_missing_host():
    assert validate_next("/just/a/path") is False


def test_rejects_empty():
    assert validate_next("") is False
