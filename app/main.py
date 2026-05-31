import sys

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings, get_settings
from app.google_oauth import build_oauth
from app.security import is_allowed, load_allowlist, validate_next
from app.tokens import build_jwks, compute_kid, load_private_key


def build_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="sa6bju googleauth")
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        https_only=True,
        same_site="lax",
        # ingen domain → host-only på auth.sa6bju.se
    )

    private_key = load_private_key(settings.jwt_private_key_path)
    public_key = private_key.public_key()
    kid = compute_kid(public_key)
    oauth = build_oauth(settings)

    app.state.settings = settings
    app.state.private_key = private_key
    app.state.kid = kid
    app.state.oauth = oauth

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    def jwks() -> JSONResponse:
        return JSONResponse(build_jwks(public_key, kid))

    @app.get("/login")
    async def login(request: Request, next: str = ""):
        if not validate_next(next):
            raise HTTPException(status_code=400, detail="Ogiltig next-parameter")
        request.session["next"] = next
        redirect_uri = f"{settings.base_url}/auth/callback"
        return await oauth.google.authorize_redirect(request, redirect_uri)

    return app


def _build_default() -> FastAPI:
    """Modulnivå-app för uvicorn (`app.main:app`). Om env saknas vid t.ex.
    testimport returneras en minimal app istället för att krascha importen —
    testerna använder build_app(settings) direkt med en temp-nyckel."""
    try:
        return build_app(get_settings())
    except Exception as exc:
        # Förväntat vid testimport (ingen .env). I produktion betyder det dock
        # en felkonfiguration — logga tydligt så den syns i journalctl istället
        # för att tjänsten startar tyst trasig.
        print(f"VARNING: googleauth kunde inte konfigureras: {exc!r}", file=sys.stderr)
        fallback = FastAPI(title="sa6bju googleauth (unconfigured)")

        @fallback.get("/healthz")
        def healthz() -> dict:
            return {"status": "ok"}

        return fallback


app = _build_default()
