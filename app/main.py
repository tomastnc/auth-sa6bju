import sys

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings, get_settings
from app.google_oauth import build_oauth
from app.security import is_allowed, load_allowlist, validate_next
from app.tokens import build_jwks, compute_kid, load_private_key, mint_session_token


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

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get("userinfo") or {}
        email = (userinfo.get("email") or "").strip()
        verified = bool(userinfo.get("email_verified"))
        sub = (userinfo.get("sub") or "").strip()

        # Läses per request med flit: en borttagning ur listan slår igenom
        # direkt utan omstart (kompletterar nyckelrotation som återkallning).
        allowlist = load_allowlist(settings.allowed_emails_path)
        # sub är den stabila identiteten appar nycklar på — kräv den, annars
        # vore en tom sub semantiskt fel. verified + allowlist = fail-closed.
        if not sub or not verified or not is_allowed(email, allowlist):
            raise HTTPException(status_code=403, detail="Åtkomst nekad")

        jwt_token = mint_session_token(
            sub=sub,
            email=email,
            email_verified=verified,
            name=userinfo.get("name", ""),
            private_key=app.state.private_key,
            kid=app.state.kid,
            issuer=settings.issuer,
            audience=settings.audience,
        )
        # Omvalidera trots att next redan validerades i /login och låg i den
        # signerade sessionen — så redirect-säkerheten inte hänger på att
        # session_secret aldrig läcker (defense-in-depth mot open redirect).
        raw_next = request.session.pop("next", "")
        next_url = raw_next if validate_next(raw_next) else settings.base_url
        response = RedirectResponse(next_url, status_code=302)
        response.set_cookie(
            key=settings.cookie_name,
            value=jwt_token,
            domain=settings.cookie_domain,
            max_age=settings.cookie_max_age,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/me")
    def me(request: Request):
        token = request.cookies.get(settings.cookie_name)
        if not token:
            raise HTTPException(status_code=401, detail="Ingen session")
        try:
            claims = jwt.decode(
                token, public_key, algorithms=["EdDSA"],
                audience=settings.audience, issuer=settings.issuer,
            )
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Ogiltig token")
        return {"email": claims["email"], "name": claims.get("name"), "sub": claims["sub"]}

    @app.get("/logout")
    def logout(next: str = ""):
        target = next if validate_next(next) else settings.base_url
        response = RedirectResponse(target, status_code=302)
        # Matcha originalcookiens attribut så även konservativa webbläsare
        # säkert rensar den.
        response.delete_cookie(
            key=settings.cookie_name,
            domain=settings.cookie_domain,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

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
