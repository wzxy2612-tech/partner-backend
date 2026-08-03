"""AEAD for outbox token payloads.

The invitation token is never stored in plaintext. invitations holds only
sha256(token), which is what makes a database leak non-redeemable, and delivery
after commit needs the plaintext back -- so the outbox carries it encrypted.

AES-256-GCM. The key comes from configuration (in production: a KMS or secret
manager), never from the database and never from source. key_version is stored
per row so a rotation can decrypt old rows with the previous key while writing
new ones with the current key.

THE AAD IS THE PART THAT MATTERS

Additional Authenticated Data is not encrypted; it is authenticated. Decryption
fails unless the same AAD is supplied. Binding it to

    outbox_event_id | invitation_id | partner_id | event_type

means a ciphertext lifted from one row and pasted onto another will not decrypt:
the row it now sits in produces different AAD. Without this, an attacker with
UPDATE on outbox_events could move a known-good ciphertext onto an event
pointing at a different invitation and have the dispatcher mail that token to an
address of their choosing. Encryption alone would not stop that -- the
ciphertext is valid, it is just in the wrong place. The binding is what makes
"valid" and "in the right place" the same question.

NOTHING HERE LOGS. Not the token, not the plaintext, not the ciphertext, and not
the contents of a decryption failure -- a failure is reported as the fact that
it failed, because the interesting part of the message would be the material we
are protecting.
"""
from __future__ import annotations

import os
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-256-GCM: 32-byte key, 12-byte nonce (the size GCM is specified for).
KEY_BYTES = 32
NONCE_BYTES = 12

CURRENT_KEY_VERSION = 1


class OutboxCryptoError(RuntimeError):
    """Encryption or decryption failed.

    Deliberately carries no detail about the material involved. A caller can
    know that a payload could not be decrypted; it cannot learn anything about
    the payload from the exception.
    """


def _keyring() -> dict[int, bytes]:
    """version -> key, from the environment.

    OUTBOX_KEYS holds `version:hex` pairs, newest last, e.g.
        OUTBOX_KEYS=1:aabb...,2:ccdd...
    A single key is the common case. Multiple entries exist so a rotation can
    still decrypt rows written under the old version.

    The dev default is a fixed all-zero key so the test suite and `make up` work
    without ceremony. It is refused when APP_ENV says production: a
    'the key is in the repo' deployment is worse than no encryption, because it
    reads as protection.
    """
    raw = os.environ.get("OUTBOX_KEYS", "").strip()
    if not raw:
        if os.environ.get("APP_ENV", "dev").lower() in {"prod", "production"}:
            raise OutboxCryptoError(
                "OUTBOX_KEYS is unset. Refusing the development key in "
                "production -- outbox token payloads would be readable by "
                "anyone with the source.")
        return {CURRENT_KEY_VERSION: b"\x00" * KEY_BYTES}

    keys: dict[int, bytes] = {}
    for part in raw.split(","):
        version, _, hex_key = part.strip().partition(":")
        key = bytes.fromhex(hex_key)
        if len(key) != KEY_BYTES:
            raise OutboxCryptoError(
                f"key version {version} is {len(key)} bytes, expected {KEY_BYTES}")
        keys[int(version)] = key
    return keys


def build_aad(*, event_id: UUID, invitation_id: UUID, partner_id: UUID,
              event_type: str) -> bytes:
    """The row identity a ciphertext is bound to.

    Every field is part of "which invitation, for which tenant, delivered by
    which event". Moving the ciphertext changes at least one of them, and GCM
    then refuses to authenticate it.
    """
    return "|".join(
        [str(event_id), str(invitation_id), str(partner_id), event_type]
    ).encode()


def encrypt_token(token: str, aad: bytes,
                  key_version: int = CURRENT_KEY_VERSION) -> tuple[bytes, bytes]:
    """-> (ciphertext, nonce). A fresh random nonce per call: GCM's security
    collapses if a nonce is ever reused under the same key."""
    keys = _keyring()
    if key_version not in keys:
        raise OutboxCryptoError(f"no key for version {key_version}")
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(keys[key_version]).encrypt(nonce, token.encode(), aad)
    return ct, nonce


def decrypt_token(ciphertext: bytes, nonce: bytes, aad: bytes,
                  key_version: int = CURRENT_KEY_VERSION) -> str:
    """-> plaintext token, or OutboxCryptoError.

    A mismatched AAD lands here as a failure, which is the intended behaviour:
    a ciphertext that has been moved to another row is not "wrong data", it is
    unauthenticated data, and it is refused as such.
    """
    keys = _keyring()
    if key_version not in keys:
        raise OutboxCryptoError(f"no key for version {key_version}")
    try:
        return AESGCM(keys[key_version]).decrypt(nonce, ciphertext, aad).decode()
    except Exception as exc:  # InvalidTag and anything else
        # No detail, deliberately: the useful content of this message would be
        # the material being protected.
        raise OutboxCryptoError("outbox payload failed authentication") from exc
