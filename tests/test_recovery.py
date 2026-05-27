import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yubivault.recovery import CODE_LEN, generate_code, generate_codes, normalize


def test_generate_code_format():
    code = generate_code()
    assert code.count("-") == 3
    parts = code.split("-")
    assert all(len(p) == 4 for p in parts)
    assert len(code.replace("-", "")) == CODE_LEN


def test_codes_are_unique():
    codes = generate_codes(20)
    assert len(set(codes)) == 20


def test_normalize_strips_dashes_and_uppercases():
    code = generate_code()
    canonical = normalize(code)
    assert b"-" not in canonical
    assert canonical == code.replace("-", "").encode("ascii")


def test_normalize_fixes_ambiguity():
    # User types lowercase + ambiguous chars — they normalize to canonical.
    assert normalize("oloi-1234-abcd-efgh") == normalize("0101-1234-ABCD-EFGH")


def test_normalize_rejects_wrong_length():
    try:
        normalize("ABC")
    except ValueError:
        return
    raise AssertionError("short code should be rejected")


def test_normalize_rejects_invalid_chars():
    try:
        normalize("XXXX-XXXX-XXXX-XX@@")
    except ValueError:
        return
    raise AssertionError("invalid chars should be rejected")


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
