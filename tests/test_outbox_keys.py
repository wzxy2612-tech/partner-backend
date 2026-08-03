"""Key configuration and rotation.

Two reported defects, one root each:

  #3  OUTBOX_KEYS unset fell back to a fixed all-zero key unless APP_ENV said
      production -- and the bundled compose file set neither. Every `make up`
      encrypted invitation tokens under a value printed in this repository.

  #6  CURRENT_KEY_VERSION was the literal 1. Configuring only a version 2 key
      made every enqueue fail with "no key for version 1"; configuring both left
      new events written under version 1 forever. A key you cannot stop using is
      not a key you can rotate away from after a leak.

These tests set the environment directly rather than going through the app
config object, because the environment is where the failures were.
"""
import uuid

import pytest

from app.services.outbox_crypto import (KEYS_ENV, CURRENT_VERSION_ENV,
                                        OutboxCryptoError, build_aad,
                                        current_key_version, decrypt_token,
                                        encrypt_token, validate_outbox_config)

KEY_A = "aa" * 32
KEY_B = "bb" * 32


def _aad():
    return build_aad(event_id=uuid.uuid4(), invitation_id=uuid.uuid4(),
                     partner_id=uuid.uuid4(), event_type="invitation.created")


# --- #3: there is no key unless someone provides one ------------------------

def test_an_unset_keyring_is_refused(monkeypatch):
    """No fallback, in any environment.

    The old guard asked whether APP_ENV said production, so every deployment
    that had not thought about APP_ENV -- which is every deployment that had not
    thought about keys either -- got the repository's key and ciphertext that
    read as protection. A narrower branch would have the same shape; the branch
    is gone.
    """
    monkeypatch.delenv(KEYS_ENV, raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    with pytest.raises(OutboxCryptoError) as exc:
        encrypt_token("tok", _aad())
    assert KEYS_ENV in str(exc.value)


def test_a_malformed_key_is_refused_without_naming_the_material(monkeypatch):
    """Configuration errors must be legible; key material must not be.

    The message identifies which version failed and how, and never echoes the
    value -- an error string is one of the easier places for a secret to end up
    in a log aggregator.
    """
    monkeypatch.setenv(KEYS_ENV, "1:not-hex-at-all")
    with pytest.raises(OutboxCryptoError) as exc:
        current_key_version()
    message = str(exc.value)
    assert "version 1" in message
    assert "not-hex-at-all" not in message


def test_a_short_key_is_refused(monkeypatch):
    """AES-256 needs 32 bytes. A 16-byte value is a valid hex string and a
    different cipher, which would otherwise be accepted silently.
    """
    monkeypatch.setenv(KEYS_ENV, "1:" + "cc" * 16)
    with pytest.raises(OutboxCryptoError):
        current_key_version()


# --- #6: which version is current ------------------------------------------

def test_one_key_needs_no_naming(monkeypatch):
    """With a single key there is no other answer the question could have, so
    requiring the operator to state it would be ceremony that teaches people to
    set variables without reading them.
    """
    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A}")
    monkeypatch.delenv(CURRENT_VERSION_ENV, raising=False)
    assert current_key_version() == 1


def test_two_keys_make_the_current_version_required(monkeypatch):
    """The fix for #6, at its root.

    The old behaviour inferred version 1 forever, so adding a second key changed
    nothing and the leaked key stayed in use. Rather than inferring "newest" --
    which would be a guess about intent, and the wrong one during a rollback --
    the configuration becomes invalid. Adding a key is exactly when the question
    needs asking, so the system asks instead of assuming.
    """
    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A},2:{KEY_B}")
    monkeypatch.delenv(CURRENT_VERSION_ENV, raising=False)
    with pytest.raises(OutboxCryptoError) as exc:
        current_key_version()
    assert CURRENT_VERSION_ENV in str(exc.value)


def test_the_current_version_must_be_in_the_keyring(monkeypatch):
    """Naming a version with no key behind it fails at validation rather than at
    the first onboarding commit -- which is what validate_outbox_config exists
    for.
    """
    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A}")
    monkeypatch.setenv(CURRENT_VERSION_ENV, "2")
    with pytest.raises(OutboxCryptoError):
        validate_outbox_config()


def test_a_non_integer_current_version_is_refused(monkeypatch):
    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A}")
    monkeypatch.setenv(CURRENT_VERSION_ENV, "latest")
    with pytest.raises(OutboxCryptoError):
        validate_outbox_config()


# --- the version travels with the ciphertext --------------------------------

def test_encryption_reports_the_version_it_used(monkeypatch):
    """The one-adjudicator assertion.

    enqueue_invitation used to write CURRENT_KEY_VERSION into the row as a
    SECOND read of the same fact. They agreed while it was a constant. Once it
    became configuration they could diverge, and the failure is silent at write
    time -- the row records a version it was not encrypted under, and nobody
    finds out until a dispatcher cannot decrypt it, possibly after the other key
    is gone.
    """
    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A},2:{KEY_B}")
    monkeypatch.setenv(CURRENT_VERSION_ENV, "2")

    aad = _aad()
    ciphertext, nonce, version = encrypt_token("a-token", aad)
    assert version == 2, "the reported version must be the one actually used"
    assert decrypt_token(ciphertext, nonce, aad, version) == "a-token"

    # And it really was key 2: version 1 must not open it.
    with pytest.raises(OutboxCryptoError):
        decrypt_token(ciphertext, nonce, aad, 1)


# --- rotation, end to end ---------------------------------------------------

def test_rotation_reads_old_rows_and_writes_new_ones(monkeypatch):
    """The whole point of storing key_version per row.

    An event written before a rotation must stay readable after it, and events
    written after must use the new key. Asserted together because either alone
    is satisfiable by doing nothing: never rotating passes the first, and losing
    the old key passes the second.
    """
    aad_old = _aad()
    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A}")
    monkeypatch.delenv(CURRENT_VERSION_ENV, raising=False)
    old_ct, old_nonce, old_version = encrypt_token("older-token", aad_old)
    assert old_version == 1

    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A},2:{KEY_B}")
    monkeypatch.setenv(CURRENT_VERSION_ENV, "2")

    assert decrypt_token(old_ct, old_nonce, aad_old, old_version) == "older-token"

    aad_new = _aad()
    new_ct, new_nonce, new_version = encrypt_token("newer-token", aad_new)
    assert new_version == 2
    assert decrypt_token(new_ct, new_nonce, aad_new, new_version) == "newer-token"


def test_retiring_a_key_makes_its_rows_undecryptable_not_crashing(monkeypatch):
    """Removing the old key is the last step of a rotation, and it has to be a
    step someone can take deliberately.

    A row still holding version 1 then raises OutboxCryptoError, which
    dispatch_pending already routes to dead-letter rather than retrying -- no
    amount of retrying restores a deleted key. What matters here is that the
    failure is the typed error and not something that escapes the dispatcher.
    """
    aad = _aad()
    monkeypatch.setenv(KEYS_ENV, f"1:{KEY_A}")
    monkeypatch.delenv(CURRENT_VERSION_ENV, raising=False)
    ciphertext, nonce, version = encrypt_token("stranded-token", aad)

    monkeypatch.setenv(KEYS_ENV, f"2:{KEY_B}")
    monkeypatch.delenv(CURRENT_VERSION_ENV, raising=False)
    with pytest.raises(OutboxCryptoError) as exc:
        decrypt_token(ciphertext, nonce, aad, version)
    assert "stranded-token" not in str(exc.value)
