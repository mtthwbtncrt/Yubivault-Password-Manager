import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yubivault.csv_import import detect_format, import_csv


def _write_csv(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return Path(f.name)


def test_detect_chrome():
    headers = ["name", "url", "username", "password"]
    fmt, mapping = detect_format(headers)
    assert fmt == "chrome"
    assert mapping["password"] == "password"
    assert mapping["url"] == "url"


def test_detect_bitwarden():
    headers = ["folder", "favorite", "type", "name", "notes", "fields",
               "login_uri", "login_username", "login_password", "login_totp"]
    fmt, mapping = detect_format(headers)
    assert fmt == "bitwarden"
    assert mapping["login_password"] == "password"
    assert mapping["folder"] == "tag"


def test_detect_keepassxc():
    headers = ["Group", "Title", "Username", "Password", "URL", "Notes"]
    fmt, _ = detect_format(headers)
    assert fmt == "keepassxc"


def test_detect_generic_fallback():
    headers = ["Site", "User", "Pass", "Website", "Memo", "Category"]
    fmt, mapping = detect_format(headers)
    assert fmt == "generic"
    assert mapping["Site"] == "name"
    assert mapping["Pass"] == "password"
    assert mapping["Category"] == "tag"


def test_import_chrome_csv():
    p = _write_csv(
        "name,url,username,password,note\n"
        "github,https://github.com,alice,secret123,\n"
        "gmail,https://gmail.com,alice@gmail.com,gmailpass,personal account\n"
    )
    result = import_csv(p)
    p.unlink()
    assert result.format_detected == "chrome"
    assert len(result.entries) == 2
    assert result.entries[0].name == "github"
    assert result.entries[0].password == "secret123"
    assert result.entries[1].notes == "personal account"


def test_import_bitwarden_with_folder_tags():
    p = _write_csv(
        "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n"
        "Work/Dev,,login,github,,,https://github.com,alice,secret,\n"
        "Personal,,login,bank,,,https://bank.com,alice@gmail.com,bankpass,\n"
    )
    result = import_csv(p)
    p.unlink()
    assert result.format_detected == "bitwarden"
    assert len(result.entries) == 2
    assert "Work" in result.entries[0].tags
    assert "Dev" in result.entries[0].tags  # path split
    assert "Personal" in result.entries[1].tags


def test_import_skips_rows_with_no_password():
    p = _write_csv(
        "name,url,username,password\n"
        "good,https://x.com,alice,pass1\n"
        "no-pass,https://y.com,bob,\n"
        "\n"
        "another,https://z.com,carol,pass3\n"
    )
    result = import_csv(p)
    p.unlink()
    assert len(result.entries) == 2
    assert {e.name for e in result.entries} == {"good", "another"}
    assert result.skipped_empty >= 1


def test_import_applies_default_tag():
    p = _write_csv(
        "name,url,username,password\n"
        "github,https://github.com,alice,p1\n"
        "gitlab,https://gitlab.com,alice,p2\n"
    )
    result = import_csv(p, default_tag="imported-2026-05")
    p.unlink()
    for e in result.entries:
        assert "imported-2026-05" in e.tags


def test_import_uses_url_hostname_when_name_missing():
    p = _write_csv(
        "url,username,password\n"
        "https://example.com/login,alice,secret\n"
    )
    result = import_csv(p)
    p.unlink()
    assert len(result.entries) == 1
    assert result.entries[0].name == "example.com"


def test_import_rejects_unknown_format():
    p = _write_csv(
        "unknown_col,another_unknown\n"
        "v1,v2\n"
    )
    try:
        import_csv(p)
    except ValueError:
        p.unlink()
        return
    p.unlink()
    raise AssertionError("unknown header should raise ValueError")


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
