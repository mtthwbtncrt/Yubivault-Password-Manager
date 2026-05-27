from __future__ import annotations

import secrets
import string

# A safe printable alphabet that avoids visually ambiguous characters
# (I, l, 1, 0, O) for human-typed passwords. Excludes quotes and backslash
# to keep passwords shell-friendly.
SAFE_ALPHABET = (
    string.ascii_uppercase.replace("I", "").replace("O", "")
    + string.ascii_lowercase.replace("l", "")
    + string.digits.replace("0", "").replace("1", "")
    + "!@#$%^&*-_=+?"
)


def generate(length: int = 24, alphabet: str = SAFE_ALPHABET) -> str:
    if length < 8:
        raise ValueError("Refusing to generate password shorter than 8 chars.")
    return "".join(secrets.choice(alphabet) for _ in range(length))
