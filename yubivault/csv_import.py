"""CSV import for credentials exported from browsers / other managers.

Supported formats (auto-detected from header row):
  - Chrome / Edge / Brave   (name, url, username, password [, note])
  - Firefox                 (url, username, password, ...)
  - Bitwarden               (folder, name, login_uri, login_username, login_password, notes)
  - KeePassXC               (Group, Title, Username, Password, URL, Notes)
  - 1Password (CSV export)  (Title, Url, Username, Password, Notes, Type)
  - LastPass                (url, username, password, totp, extra, name, grouping, fav)
  - Generic                 (name|title, username, password, url|website, notes, tags|category|folder|group)

Any unrecognised header set falls back to "generic" with best-effort mapping.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ImportedEntry:
    name: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class ImportResult:
    entries: list[ImportedEntry]
    format_detected: str
    rows_seen: int
    skipped_empty: int


# Map of normalised header → canonical entry field.
# Each format defines its own preferred mapping; the detector picks the format
# whose required headers all appear.
_FORMATS = [
    {
        "name": "bitwarden",
        "required": {"name", "login_username", "login_password"},
        "map": {
            "name": "name",
            "login_username": "username",
            "login_password": "password",
            "login_uri": "url",
            "notes": "notes",
            "folder": "tag",
        },
    },
    {
        "name": "keepassxc",
        "required": {"title", "password"},
        "map": {
            "title": "name",
            "username": "username",
            "password": "password",
            "url": "url",
            "notes": "notes",
            "group": "tag",
        },
    },
    {
        "name": "1password",
        "required": {"title", "password"},
        "map": {
            "title": "name",
            "username": "username",
            "password": "password",
            "url": "url",
            "urls": "url",
            "notes": "notes",
            "tags": "tags",
        },
    },
    {
        # Chrome must come before LastPass — LastPass's required set is a
        # subset of Chrome's headers, so otherwise LastPass wins on Chrome CSVs.
        "name": "chrome",
        "required": {"name", "url", "username", "password"},
        "map": {
            "name": "name",
            "username": "username",
            "password": "password",
            "url": "url",
            "note": "notes",
            "notes": "notes",
        },
    },
    {
        "name": "lastpass",
        "required": {"name", "password", "url", "grouping"},  # grouping disambiguates from Chrome
        "map": {
            "name": "name",
            "username": "username",
            "password": "password",
            "url": "url",
            "extra": "notes",
            "grouping": "tag",
        },
    },
    {
        "name": "firefox",
        "required": {"url", "username", "password"},
        "map": {
            "url": "url",
            "username": "username",
            "password": "password",
            "httprealm": "notes",
        },
    },
    # Generic: any header that includes some recognisable subset. Tried last.
    {
        "name": "generic",
        "required": set(),  # always matches as a fallback
        "map": {
            "name": "name",
            "title": "name",
            "site": "name",
            "username": "username",
            "user": "username",
            "login": "username",
            "email": "username",
            "password": "password",
            "pass": "password",
            "secret": "password",
            "url": "url",
            "uri": "url",
            "website": "url",
            "notes": "notes",
            "memo": "notes",
            "comment": "notes",
            "tags": "tags",
            "category": "tag",
            "folder": "tag",
            "group": "tag",
            "grouping": "tag",
        },
    },
]


def _normalise(header: str) -> str:
    return header.strip().lower().replace(" ", "_").replace("-", "_")


def detect_format(headers: list[str]) -> tuple[str, dict[str, str]]:
    norm = [_normalise(h) for h in headers]
    norm_set = set(norm)
    for fmt in _FORMATS:
        if fmt["required"].issubset(norm_set) or fmt["name"] == "generic":
            mapping = {}
            for i, h in enumerate(norm):
                if h in fmt["map"]:
                    mapping[headers[i]] = fmt["map"][h]
            # Require AT LEAST a name (or url to fall back to) AND a password column.
            target_fields = set(mapping.values())
            if "password" in target_fields and ("name" in target_fields or "url" in target_fields):
                return fmt["name"], mapping
    return "unknown", {}


def import_csv(path: Path, default_tag: str | None = None) -> ImportResult:
    """Read a CSV at `path` and return parsed entries.

    Behaviour:
      - First row is treated as the header.
      - Empty rows are skipped (counted in `skipped_empty`).
      - Rows missing both name and url AND missing password are skipped.
      - If `default_tag` is set, every imported entry gets that tag.
      - If an entry's tag column has a path-like value (e.g. "Work/Bank"),
        each segment becomes a separate tag.
    """
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        try:
            headers = next(reader)
        except StopIteration:
            return ImportResult([], "empty", 0, 0)

        fmt, mapping = detect_format(headers)
        if not mapping:
            raise ValueError(
                "Could not detect CSV format. The header row must contain at least a "
                "name/title/url column and a password column. "
                f"Headers seen: {headers!r}"
            )

        entries: list[ImportedEntry] = []
        rows_seen = 0
        skipped_empty = 0
        for raw in reader:
            rows_seen += 1
            if not any((c or "").strip() for c in raw):
                skipped_empty += 1
                continue
            row = dict(zip(headers, raw))
            entry = _row_to_entry(row, mapping, default_tag)
            if entry is None:
                skipped_empty += 1
                continue
            entries.append(entry)

        return ImportResult(entries, fmt, rows_seen, skipped_empty)


def _row_to_entry(
    row: dict[str, str], mapping: dict[str, str], default_tag: str | None
) -> ImportedEntry | None:
    name = ""
    username = ""
    password = ""
    url = ""
    notes = ""
    tags: list[str] = []

    for src_col, target in mapping.items():
        val = (row.get(src_col) or "").strip()
        if not val:
            continue
        if target == "name" and not name:
            name = val
        elif target == "username" and not username:
            username = val
        elif target == "password" and not password:
            password = val
        elif target == "url" and not url:
            url = val
        elif target == "notes":
            notes = (notes + ("\n" if notes else "") + val).strip()
        elif target == "tag":
            # Path-like values become multiple tags ("Work/Bank" → ["Work", "Bank"])
            for piece in val.replace("\\", "/").split("/"):
                p = piece.strip()
                if p and p not in tags:
                    tags.append(p)
        elif target == "tags":
            for piece in val.replace(";", ",").split(","):
                p = piece.strip()
                if p and p not in tags:
                    tags.append(p)

    if not password:
        return None
    if not name:
        # Fall back to using the hostname from the URL.
        from urllib.parse import urlparse
        try:
            name = urlparse(url).netloc or url or "(unnamed)"
        except Exception:
            name = url or "(unnamed)"

    if default_tag and default_tag not in tags:
        tags.append(default_tag)

    return ImportedEntry(
        name=name, username=username, password=password,
        url=url, notes=notes, tags=tags,
    )
