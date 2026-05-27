import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yubivault.secure import Secret, wipe


def test_wipe_zeros_bytearray():
    b = bytearray(b"hello world")
    wipe(b)
    assert b == bytearray(11)


def test_secret_passes_to_bytes_consumers():
    s = Secret(b"abc")
    assert len(s) == 3
    assert bytes(s) == b"abc"
    s.wipe()


def test_secret_context_manager_wipes():
    s = Secret(b"sensitive")
    with s as inner:
        assert bytes(inner) == b"sensitive"
    assert bytes(s) == b"\x00" * 9


def test_secret_double_wipe_safe():
    s = Secret(b"abc")
    s.wipe()
    s.wipe()  # must not raise


def test_secret_repr_does_not_leak():
    s = Secret(b"P@ssw0rd!")
    assert "P@ssw0rd" not in repr(s)
    assert "len=9" in repr(s)


def test_secret_works_with_crypto_via_bytes_copy():
    # PyNaCl strictly requires `bytes`. Secret stores secrets in a wiped
    # bytearray; at AEAD call sites we hand over a `bytes(...)` copy. That
    # copy is transient and uncontrollable — a documented Python limitation.
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_decrypt,
        crypto_aead_xchacha20poly1305_ietf_encrypt,
    )

    key = Secret(os.urandom(32))
    nonce = os.urandom(24)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(b"plaintext", b"", nonce, bytes(key))
    pt = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, b"", nonce, bytes(key))
    assert pt == b"plaintext"
    key.wipe()
    # After wipe, bytes(key) returns 32 zero bytes — caller cannot accidentally
    # decrypt with a wiped key.
    assert bytes(key) == b"\x00" * 32


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
