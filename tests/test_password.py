"""Pure unit tests for password hashing -- no DB, no network."""
from app.auth.password import hash_password, verify_password


def test_hash_verify_roundtrip():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)


def test_wrong_password_fails():
    stored = hash_password("s3cret")
    assert not verify_password("nope", stored)


def test_salt_makes_hashes_unique():
    assert hash_password("same") != hash_password("same")


def test_tampered_hash_fails():
    stored = hash_password("s3cret")
    tampered = stored[:-2] + ("aa" if not stored.endswith("aa") else "bb")
    assert not verify_password("s3cret", tampered)


def test_malformed_stored_is_rejected():
    assert not verify_password("x", "not-a-valid-hash")
