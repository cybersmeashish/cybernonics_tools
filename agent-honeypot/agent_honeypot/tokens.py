"""Generators for realistic-looking but non-functional decoy secrets.

Tokens are generated at plant time and never committed to source control.
Every token is high-entropy and unique per honeypot per agent instance, which
is what makes a trigger both high-confidence and attributable.
"""
import secrets
import string

_UP = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def _rand(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def cloud_access_key_id():
    """AWS-shaped access key id (decoy, not valid)."""
    return "AKIA" + _rand(_UP, 16)


def cloud_secret_key():
    return _rand(_ALNUM + "+/", 40)


def api_token(prefix="sk_live_"):
    return prefix + _rand(_ALNUM, 40)


def password(n=24):
    return _rand(_ALNUM + "!#%+=", n)


def hex_id(n=16):
    return secrets.token_hex(n // 2 + 1)[:n]


def opaque(n=32):
    return _rand(string.ascii_lowercase + string.digits, n)
