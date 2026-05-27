from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

KEY_BYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES        # 32
NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES     # 24
SALT_BYTES = 16


@dataclass(frozen=True)
class KdfParams:
    memory_cost: int = 256 * 1024   # 256 MiB
    time_cost: int = 4
    parallelism: int = 4

    def to_dict(self) -> dict:
        return {
            "name": "argon2id",
            "m": self.memory_cost,
            "t": self.time_cost,
            "p": self.parallelism,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        if d.get("name") != "argon2id":
            raise ValueError(f"Unsupported KDF: {d.get('name')!r}")
        return cls(memory_cost=d["m"], time_cost=d["t"], parallelism=d["p"])


def derive_key(secret: bytes, salt: bytes, params: KdfParams) -> bytes:
    if len(salt) < SALT_BYTES:
        raise ValueError("salt too short")
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_BYTES,
        type=Type.ID,
    )


def random_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def random_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def random_nonce() -> bytes:
    return secrets.token_bytes(NONCE_BYTES)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes")
    nonce = random_nonce()
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


def wrap_master_key(
    master_key: bytes,
    unwrap_secret: bytes,
    salt: bytes,
    params: KdfParams,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    wrap_key = derive_key(unwrap_secret, salt, params)
    try:
        return aead_encrypt(wrap_key, master_key, aad)
    finally:
        _wipe(wrap_key)


def unwrap_master_key(
    wrapped: bytes,
    nonce: bytes,
    unwrap_secret: bytes,
    salt: bytes,
    params: KdfParams,
    aad: bytes = b"",
) -> bytes:
    wrap_key = derive_key(unwrap_secret, salt, params)
    try:
        return aead_decrypt(wrap_key, nonce, wrapped, aad)
    finally:
        _wipe(wrap_key)


def _wipe(buf) -> None:
    # If we got a mutable bytearray, scrub it in place.
    # For immutable bytes there is no safe wipe; the binding just goes away.
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    del buf
