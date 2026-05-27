import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yubivault.crypto import (
    KEY_BYTES,
    NONCE_BYTES,
    KdfParams,
    aead_decrypt,
    aead_encrypt,
    derive_key,
    random_key,
    random_salt,
    unwrap_master_key,
    wrap_master_key,
)


def test_aead_roundtrip():
    key = random_key()
    nonce, ct = aead_encrypt(key, b"hello world", aad=b"header")
    assert len(nonce) == NONCE_BYTES
    pt = aead_decrypt(key, nonce, ct, aad=b"header")
    assert pt == b"hello world"


def test_aead_rejects_wrong_aad():
    key = random_key()
    nonce, ct = aead_encrypt(key, b"hello", aad=b"good")
    try:
        aead_decrypt(key, nonce, ct, aad=b"bad")
    except Exception:
        return
    raise AssertionError("decryption with wrong AAD should fail")


def test_aead_rejects_tampered_ciphertext():
    key = random_key()
    nonce, ct = aead_encrypt(key, b"hello world")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    try:
        aead_decrypt(key, nonce, bytes(tampered))
    except Exception:
        return
    raise AssertionError("decryption with tampered ciphertext should fail")


def test_kdf_deterministic_same_inputs():
    salt = random_salt()
    params = KdfParams(memory_cost=8 * 1024, time_cost=1, parallelism=1)  # fast for test
    k1 = derive_key(b"passphrase", salt, params)
    k2 = derive_key(b"passphrase", salt, params)
    assert k1 == k2
    assert len(k1) == KEY_BYTES


def test_kdf_different_salt_different_key():
    params = KdfParams(memory_cost=8 * 1024, time_cost=1, parallelism=1)
    k1 = derive_key(b"passphrase", random_salt(), params)
    k2 = derive_key(b"passphrase", random_salt(), params)
    assert k1 != k2


def test_wrap_unwrap_roundtrip():
    master = random_key()
    salt = random_salt()
    params = KdfParams(memory_cost=8 * 1024, time_cost=1, parallelism=1)
    nonce, wrapped = wrap_master_key(master, b"unlock-secret", salt, params, aad=b"slot-0")
    recovered = unwrap_master_key(wrapped, nonce, b"unlock-secret", salt, params, aad=b"slot-0")
    assert recovered == master


def test_wrap_rejects_wrong_secret():
    master = random_key()
    salt = random_salt()
    params = KdfParams(memory_cost=8 * 1024, time_cost=1, parallelism=1)
    nonce, wrapped = wrap_master_key(master, b"right-secret", salt, params)
    try:
        unwrap_master_key(wrapped, nonce, b"wrong-secret", salt, params)
    except Exception:
        return
    raise AssertionError("unwrap with wrong secret should fail")


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
