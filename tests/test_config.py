from app.config import Settings


def test_settings_reads_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SESSION_SECRET", "sess")
    monkeypatch.setenv("JWT_PRIVATE_KEY_PATH", "/tmp/key.pem")
    monkeypatch.setenv("ALLOWED_EMAILS_PATH", "/tmp/allowed.txt")
    s = Settings()
    assert s.google_client_id == "cid"
    assert s.cookie_domain == ".sa6bju.se"           # default
    assert s.issuer == "https://auth.sa6bju.se"      # default
    assert s.audience == "sa6bju.se"                 # default
    assert s.cookie_name == "sa6bju_session"         # default
