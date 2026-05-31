"""Säkerhetshjälpare: next-validering och allowlist."""
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_HOST = "sa6bju.se"


def validate_next(next_url: str) -> bool:
    """Sant endast om next_url är en absolut https-URL vars host är
    sa6bju.se eller en subdomän därtill. Skyddar mot open redirect.

    Skyddar /login mot open redirect: bara mål inom sa6bju.se accepteras.
    """
    if not next_url:
        return False
    parsed = urlparse(next_url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return host == ALLOWED_HOST or host.endswith("." + ALLOWED_HOST)


def load_allowlist(path: Path) -> set[str]:
    """Läser allowlist-filen: en e-post per rad, '#' = kommentar.
    Saknad fil ger tom mängd (= ingen släpps in)."""
    path = Path(path)
    if not path.exists():
        return set()
    emails = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        emails.add(line.lower())
    return emails


def is_allowed(email: str, allowlist: set[str]) -> bool:
    return email.strip().lower() in allowlist
