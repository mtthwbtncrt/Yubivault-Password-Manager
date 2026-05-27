import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yubivault.display import entries_table, filter_entries, format_table, tag_counts


def _entries():
    return {
        "github.com": {"username": "alice", "url": "https://github.com",
                       "tags": ["dev", "work"]},
        "gitlab.com": {"username": "alice", "url": "https://gitlab.com",
                       "tags": ["dev", "work"]},
        "bank.com": {"username": "alice@gmail.com", "url": "https://bank.com",
                     "tags": ["finance"]},
        "blog.local": {"username": "", "url": "", "tags": []},
    }


def test_format_table_basic():
    out = format_table(["A", "B"], [["x", "y"], ["xxx", "yyy"]])
    assert "A" in out and "B" in out
    assert "xxx" in out and "yyy" in out
    assert "-" in out


def test_format_table_truncates_long_cells():
    long = "x" * 100
    out = format_table(["A"], [[long]], max_col=20)
    # No cell longer than 20 chars
    for line in out.splitlines():
        for cell in line.split("  "):
            assert len(cell) <= 20


def test_filter_by_tag():
    e = _entries()
    devs = filter_entries(e, tag="dev")
    assert set(devs) == {"github.com", "gitlab.com"}
    assert filter_entries(e, tag="nonexistent") == {}


def test_filter_by_query():
    e = _entries()
    hits = filter_entries(e, query="alice@")
    assert set(hits) == {"bank.com"}
    hits2 = filter_entries(e, query="dev")  # matches tag
    assert set(hits2) == {"github.com", "gitlab.com"}


def test_filter_by_query_and_tag():
    e = _entries()
    hits = filter_entries(e, query="git", tag="dev")
    assert set(hits) == {"github.com", "gitlab.com"}


def test_tag_counts_sorted_by_count_desc():
    e = _entries()
    counts = tag_counts(e)
    # dev and work each appear twice; finance once
    counts_dict = dict(counts)
    assert counts_dict["dev"] == 2
    assert counts_dict["work"] == 2
    assert counts_dict["finance"] == 1
    # First entry should be one of the count=2 tags
    assert counts[0][1] >= counts[-1][1]


def test_entries_table_includes_tags_column():
    e = _entries()
    out = entries_table(e)
    assert "TAGS" in out
    assert "dev" in out
    assert "finance" in out


def test_entries_table_empty():
    assert "empty" in entries_table({}).lower()


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
