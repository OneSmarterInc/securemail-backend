from argon2 import PasswordHasher, Type
from django.contrib.auth.hashers import PBKDF2PasswordHasher, check_password, make_password


def test_new_passwords_use_salted_argon2id():
    first = make_password("Synthetic-password-only!")
    second = make_password("Synthetic-password-only!")
    assert first.startswith("argon2$argon2id$")
    assert first != second
    assert check_password("Synthetic-password-only!", first)
    assert not check_password("wrong", first)


def test_legacy_password_upgrades_after_verification():
    old = PBKDF2PasswordHasher().encode("Synthetic-password-only!", "synthetic-test-salt")
    updated = []
    assert check_password(
        "Synthetic-password-only!", old, setter=lambda raw: updated.append(make_password(raw))
    )
    assert updated[0].startswith("argon2$argon2id$")


def test_custodian_hash_is_argon2id():
    hashed = PasswordHasher(type=Type.ID).hash("Synthetic-custodian-password!")
    assert hashed.startswith("$argon2id$")
    assert PasswordHasher().verify(hashed, "Synthetic-custodian-password!")
