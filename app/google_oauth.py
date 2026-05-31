"""Authlib-OAuth-registret konfigurerat mot Google (OpenID Connect)."""
from authlib.integrations.starlette_client import OAuth

from app.config import Settings


def build_oauth(settings: Settings) -> OAuth:
    oauth = OAuth()
    oauth.register(
        name="google",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth
