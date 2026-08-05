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

KEYS_ENV = "OUTBOX_KEYS"
CURRENT_VERSION_ENV = "OUTBOX_CURRENT_KEY_VERSION"


class OutboxCryptoError(RuntimeError):
    """Encryption or decryption failed.

    Deliberately carries no detail about the material involved. A caller can
    know that a payload could not be decrypted; it cannot learn anything about
    the payload from the exception.
    """


def _keyring() -> dict[int, bytes]:
    """version -> key, from the environment.

    OUTBOX_KEYS holds `version:hex` pairs, e.g.
        OUTBOX_KEYS=1:aabb...,2:ccdd...
    A single key is the common case. Multiple entries exist so a rotation can
    still decrypt rows written under the old version.

    THERE IS NO DEFAULT KEY, and the absence of one is the point.

    This used to fall back to a fixed all-zero key whenever OUTBOX_KEYS was
    unset and APP_ENV did not say production -- which the bundled compose file
    left unset, so every `make up` encrypted invitation tokens under a key
    printed in this repository. The ciphertext read as protection and was not.

    The fix is not a narrower branch. A code path that mints a known key cannot
    be misconfigured into existence if it does not exist, so the branch is gone
    and the requirement is unconditional. Tests inject their own key; deployment
    supplies a real one. Nothing infers a key from the fact that nobody set one.
    """
    raw = os.environ.get(KEYS_ENV, "").strip()
    if not raw:
        raise OutboxCryptoError(
            f"{KEYS_ENV} is unset. Set it to `version:hex` pairs, e.g. "
            f"{KEYS_ENV}=1:$(openssl rand -hex 32). There is no default key.")

    keys: dict[int, bytes] = {}
    for part in raw.split(","):
        version, sep, hex_key = part.strip().partition(":")
        if not sep:
            raise OutboxCryptoError(
                f"malformed {KEYS_ENV} entry: expected `version:hex`")
        try:
            version_number = int(version)
        except ValueError:
            raise OutboxCryptoError(
                f"key version {version!r} is not an integer") from None
        try:
            key = bytes.fromhex(hex_key)
        except ValueError:
            # The message names the version, never the material.
            raise OutboxCryptoError(
                f"key version {version_number} is not valid hex") from None
        if len(key) != KEY_BYTES:
            raise OutboxCryptoError(
                f"key version {version_number} is {len(key)} bytes, "
                f"expected {KEY_BYTES}")
        if version_number in keys:
            # A dict silently kept the LAST entry, and every check downstream
            # then passed. len(keys) stayed 1, so current_key_version() inferred
            # the version with no complaint -- the "infer only when there is no
            # other answer" rule defeated by a configuration that made two
            # answers look like one. Which key won depended on the order they
            # were written in, and nothing anywhere said which that was.
            #
            # The damage is not a failed encrypt. Rows already written under the
            # real version-1 key stop decrypting, dead-letter, and the failure
            # path clears ciphertext and nonce -- so the tokens are gone, not
            # merely unreadable. Refusing at startup is the only point where
            # this is still reversible.
            raise OutboxCryptoError(
                f"key version {version_number} appears more than once in "
                f"{KEYS_ENV}. Whichever entry won would silently become the key "
                f"for every row already written under that version. Name each "
                f"version once, and use a NEW version number to introduce a new "
                f"key.")
        keys[version_number] = key
    return keys


def current_key_version() -> int:
    """The version new payloads are encrypted under.

    This was the constant `CURRENT_KEY_VERSION = 1`, which made rotation
    impossible in two directions at once: configuring only a version 2 key made
    every enqueue fail with "no key for version 1", and configuring both left
    new events still being written under version 1 forever. A key you cannot
    stop using is not a key you can rotate away from after a leak.

    The version may be INFERRED only when the keyring holds exactly one key,
    where there is no other answer it could have. The moment a second key is
    added the configuration is invalid until someone states which is current --
    so the silent "still using the old one" outcome is not reachable. Adding a
    key is exactly the moment the question needs asking, and this makes the
    system ask it rather than assume.
    """
    keys = _keyring()
    raw = os.environ.get(CURRENT_VERSION_ENV, "").strip()

    if not raw:
        if len(keys) == 1:
            return next(iter(keys))
        raise OutboxCryptoError(
            f"{CURRENT_VERSION_ENV} is unset and {KEYS_ENV} holds "
            f"{sorted(keys)}. With more than one key the current version cannot "
            f"be inferred -- name it, or new events will be written under a "
            f"version nobody chose.")

    try:
        version = int(raw)
    except ValueError:
        raise OutboxCryptoError(
            f"{CURRENT_VERSION_ENV}={raw!r} is not an integer") from None
    if version not in keys:
        raise OutboxCryptoError(
            f"{CURRENT_VERSION_ENV}={version} is not in {KEYS_ENV} "
            f"(which holds {sorted(keys)})")
    return version


def validate_outbox_config() -> int:
    """Resolve the whole configuration once, at startup, and return the current
    version.

    _keyring() and current_key_version() are called lazily on every encrypt and
    decrypt, so a broken configuration would otherwise surface at the first
    onboarding commit rather than at boot -- an error a user sees instead of an
    error the deployment sees. Called from app.main's lifespan and from any
    dispatcher entry point.
    """
    return current_key_version()


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
                  key_version: int | None = None) -> tuple[bytes, bytes, int]:
    """-> (ciphertext, nonce, key_version). A fresh random nonce per call: GCM's
    security collapses if a nonce is ever reused under the same key.

    THE VERSION IS RETURNED, NOT LOOKED UP TWICE.

    enqueue_invitation used to call this and then separately write
    CURRENT_KEY_VERSION into the row. Two reads of the same fact, agreeing only
    because both read one constant. Once the version became configurable that
    stopped being guaranteed, and the failure is invisible at write time: the
    row records a version it was not encrypted under, and nothing notices until
    a dispatcher tries to decrypt it -- possibly days later, possibly after the
    other key is gone.

    So the version travels with the ciphertext it belongs to. The caller cannot
    record a different one without going out of its way.
    """
    keys = _keyring()
    version = current_key_version() if key_version is None else key_version
    if version not in keys:
        raise OutboxCryptoError(f"no key for version {version}")
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(keys[version]).encrypt(nonce, token.encode(), aad)
    return ct, nonce, version


def decrypt_token(ciphertext: bytes, nonce: bytes, aad: bytes,
                  key_version: int) -> str:
    """-> plaintext token, or OutboxCryptoError.

    key_version is REQUIRED. It used to default to the current version, so a
    caller that forgot to pass the row's stored version would silently try the
    current key -- which works right up until a rotation, and then fails on
    exactly the old rows the versioning exists to keep readable. The row always
    knows its own version; there is no case where guessing is correct.

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
