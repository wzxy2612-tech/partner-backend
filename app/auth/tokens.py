"""Opaque bearer tokens. The token is a high-entropy random string handed to the
client once; only its SHA-256 hash is stored, so a DB leak does not expose live
tokens. Lookups are by hash. Revocation is a DB update, not a crypto concern.
"""
import hashlib
import secrets

_TOKEN_BYTES = 32  # 256 bits


def new_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
