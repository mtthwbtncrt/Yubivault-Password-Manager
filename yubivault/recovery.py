from __future__ import annotations

import secrets

# Crockford base32 alphabet — no 0/O, 1/I/L, U confusion.
# 32 chars * 16 = 80 bits of entropy per code.
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_GROUPS = 4
GROUP_LEN = 4
CODE_LEN = CODE_GROUPS * GROUP_LEN  # 16 chars

# Normalization map per Crockford base32 spec.
_NORMALIZE_MAP = str.maketrans({
    "I": "1", "i": "1",
    "L": "1", "l": "1",
    "O": "0", "o": "0",
    "U": "V", "u": "V",
})


def generate_code() -> str:
    """Generate one human-readable recovery code, e.g. 'X8K2-9PMQ-4Z7N-RT3F'."""
    raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN))
    return "-".join(raw[i : i + GROUP_LEN] for i in range(0, CODE_LEN, GROUP_LEN))


def generate_codes(n: int = 10) -> list[str]:
    return [generate_code() for _ in range(n)]


def normalize(user_input: str) -> bytes:
    """Normalize a user-typed recovery code into canonical bytes for KDF input.

    Strips whitespace/dashes, uppercases, applies Crockford ambiguity fixes.
    Returns the canonical byte representation. Raises ValueError if invalid.
    """
    cleaned = (
        user_input.replace("-", "")
        .replace(" ", "")
        .replace("\t", "")
        .translate(_NORMALIZE_MAP)
        .upper()
    )
    if len(cleaned) != CODE_LEN:
        raise ValueError(f"Recovery code must be {CODE_LEN} characters (got {len(cleaned)})")
    for ch in cleaned:
        if ch not in ALPHABET:
            raise ValueError(f"Invalid character in recovery code: {ch!r}")
    return cleaned.encode("ascii")
