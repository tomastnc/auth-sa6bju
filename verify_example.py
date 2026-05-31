"""Referensexempel: hur en app på en annan *.sa6bju.se-subdomän verifierar
sessionscookien och läser ut vilket Google-konto den tillhör.

Kopiera in i din app. I produktion: hämta och cacha JWKS automatiskt med
`jwt.PyJWKClient` istället för att skicka in en jwks-dict:

    jwks_client = jwt.PyJWKClient("https://auth.sa6bju.se/.well-known/jwks.json")
    signing_key = jwks_client.get_signing_key_from_jwt(token).key

Cookien heter `sa6bju_session`. Den är HttpOnly → läs den serverside ur
`Cookie`-headern, inte i webbläsar-JS.

FÖRTROENDEMODELL: cookien sätts för hela `.sa6bju.se`, så ALLA subdomäner får
den med varje request. Den är HttpOnly (kan inte läsas av JS), men en komprometterad
subdomän kan ändå skicka med den mot andra subdomäner. Kör därför bara betrodd kod
på subdomäner under sa6bju.se — annars kan en sessionskapning ske inom domänen.
"""
import jwt

ISSUER = "https://auth.sa6bju.se"
AUDIENCE = "sa6bju.se"
JWKS_URL = "https://auth.sa6bju.se/.well-known/jwks.json"


def verify_cookie(token: str, *, jwks: dict | None = None) -> dict:
    """Verifierar JWT:n och returnerar dess claims (innehåller 'email', 'sub',
    'name'). Kastar jwt.InvalidTokenError om signatur/iss/aud inte stämmer.

    jwks: skicka in en JWKS-dict i tester; utelämna i produktion → hämtas från
    JWKS_URL och cachas av PyJWKClient.
    """
    header = jwt.get_unverified_header(token)
    if jwks is not None:
        match = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
        signing_key = jwt.PyJWK.from_dict(match).key
    else:
        signing_key = jwt.PyJWKClient(JWKS_URL).get_signing_key_from_jwt(token).key

    return jwt.decode(
        token, signing_key, algorithms=["EdDSA"],
        audience=AUDIENCE, issuer=ISSUER,
    )
