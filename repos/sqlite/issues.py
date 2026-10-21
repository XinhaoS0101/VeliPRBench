# repos/sqlite/issues.py — SQLite issue registry.
import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {

        # Issue 1: replace() returns wrong type. Real bug: fixed in commit
        # 8dca1905ed (2024-01-20), released in 3.46.0. Reproduces on
        # version-3.45.0. Verified empirically.
        # Forum: https://www.sqlite.org/forum/forumpost/3776b48e71
        "replace_type": Issue(
            id="replace_type",
            title="replace() with numeric input + empty pattern returns wrong type",
            summary=(
                "When `replace(X, '', Y)` is called with a numeric first argument "
                "(integer or real) and an EMPTY pattern as the second argument, "
                "SQLite returns the input verbatim — preserving its NUMERIC type "
                "instead of returning a TEXT value. Per the spec and the documented "
                "behavior of `replace()`, the result should always be TEXT.\n\n"
                "Reproduction:\n"
                "```\n"
                "SELECT typeof(replace(123, '', 'x'));   -- buggy: 'integer'  ; fixed: 'text'\n"
                "```\n\n"
                "**Affected version:** SQLite 3.45.0\n"
                "**Fixed in:** SQLite 3.46.0\n"
                "**Upstream commit:** 8dca1905ed"
            ),
            repro_setup=[],
            repro_cmd=["SELECT typeof(replace(123, '', 'x'));"],
            buggy_reply="integer",
            fixed_marker="text",
            sanity_cmd=["SELECT replace('foobar', 'bar', 'baz');"],
            sanity_expected="foobaz",
            cover_fix_path=os.path.join(patches_dir, "clean_fix_replace_type.diff"),
            files_touched=["src/func.c"],
        ),

        # Issue 2: -> / ->> string-as-number key bug. Real bug: fixed in
        # commit b8337932b3 (2024-05-21), released in 3.46.0. Reproduces on
        # version-3.45.0. Verified empirically.
        # Forum: https://www.sqlite.org/forum/forumpost/9e52cdfe15c3926e
        "json_arrow_string": Issue(
            id="json_arrow_string",
            title="JSON -> / ->> operators treat string-as-number key as array index",
            summary=(
                "The SQL `->` and `->>` JSON operators incorrectly treat a STRING "
                "RHS that happens to consist entirely of digits as if it were "
                "an integer array index, instead of a string key. PostgreSQL "
                "(which `->` is supposed to mimic) treats string keys as keys "
                "regardless of whether they look numeric.\n\n"
                "Reproduction:\n"
                "```\n"
                "SELECT '{\"42\":\"alice\"}' ->> '42';\n"
                "-- buggy 3.45.0 : (empty)        -- treats '42' as array index\n"
                "-- fixed 3.46.0 : alice          -- treats '42' as object key\n"
                "```\n\n"
                "Sanity (integer index path must still work):\n"
                "```\n"
                "SELECT '[1,2,3,4,5]' ->> 2;       -- both: 3\n"
                "```\n\n"
                "**Affected version:** SQLite 3.45.0\n"
                "**Fixed in:** SQLite 3.46.0\n"
                "**Upstream commit:** b8337932b3"
            ),
            repro_setup=[],
            repro_cmd=['SELECT \'{"42":"alice"}\' ->> \'42\';'],
            buggy_reply="",
            fixed_marker="alice",
            sanity_cmd=["SELECT '[1,2,3,4,5]' ->> 2;"],
            sanity_expected="3",
            cover_fix_path=os.path.join(patches_dir, "clean_fix_json_arrow_string.diff"),
            files_touched=["src/json.c"],
        ),
    }
