"""Small terminal formatting helpers shared by CLI and REPL."""

from __future__ import annotations

from typing import Iterable


def format_table(headers: list[str], rows: list[list[str]], max_col: int = 40) -> str:
    """Format a simple left-aligned table with column padding.

    Long cells are truncated with an ellipsis to keep one row per entry.
    Returns the whole thing as a single string with embedded newlines.
    """
    cols = list(zip(*([headers] + rows))) if rows else [(h,) for h in headers]
    widths = []
    for col in cols:
        w = max(len(_truncate(c, max_col)) for c in col)
        widths.append(w)

    def fmt_row(cells: Iterable[str]) -> str:
        return "  ".join(
            _truncate(c, max_col).ljust(w) for c, w in zip(cells, widths)
        )

    lines = [fmt_row(headers)]
    lines.append("  ".join("-" * w for w in widths))
    for r in rows:
        lines.append(fmt_row(r))
    return "\n".join(lines)


def _truncate(s: str, n: int) -> str:
    s = s or ""
    if len(s) <= n:
        return s
    if n <= 1:
        return s[:n]
    return s[: n - 1] + "…"


def entries_table(entries: dict[str, dict]) -> str:
    """Render the vault's entries as: NAME, USERNAME, URL, TAGS."""
    if not entries:
        return "(vault is empty)"
    rows = []
    for name in sorted(entries):
        e = entries[name]
        rows.append([
            name,
            e.get("username", ""),
            e.get("url", ""),
            ", ".join(e.get("tags") or []),
        ])
    return format_table(["NAME", "USERNAME", "URL", "TAGS"], rows)


def tag_counts(entries: dict[str, dict]) -> list[tuple[str, int]]:
    """Return [(tag, count), ...] sorted by count desc then name asc."""
    counts: dict[str, int] = {}
    for e in entries.values():
        for t in e.get("tags") or []:
            counts[t] = counts.get(t, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def filter_entries(
    entries: dict[str, dict],
    query: str = "",
    tag: str | None = None,
) -> dict[str, dict]:
    """Return entries matching `query` (substring on name/username/url) AND `tag`."""
    q = query.lower().strip()
    out: dict[str, dict] = {}
    for name, e in entries.items():
        if tag and tag not in (e.get("tags") or []):
            continue
        if q:
            hay = " ".join([
                name,
                e.get("username", "") or "",
                e.get("url", "") or "",
                " ".join(e.get("tags") or []),
            ]).lower()
            if q not in hay:
                continue
        out[name] = e
    return out
