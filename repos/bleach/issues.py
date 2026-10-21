import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "mutation_xss_comment_escape": Issue(
            id="mutation_xss_comment_escape",
            title="Escape HTML comments in mutation-XSS sanitizer contexts",
            summary=(
                "Bleach before 3.3.0 could preserve raw HTML comments when "
                "`bleach.clean` was called with `strip_comments=False` and "
                "specific SVG/MathML/raw-text tag allowlists. Browser reparsing "
                "could mutate the sanitized output and expose attacker-controlled "
                "tags such as `<img onerror=...>`.\n\n"
                "Real upstream source: GHSA-vv2x-vrpj-qqpq / CVE-2021-23980.\n"
                "Affected range: `<3.3.0`.\n"
                "Baseline: `v3.2.3`.\n"
                "Fixed version: `3.3.0`.\n\n"
                "The local probe calls `bleach.clean` with the advisory "
                "conditions: `svg` or `math`, `p`, a raw-text-like tag, and "
                "`strip_comments=False`. The buggy behavior preserves a raw "
                "`</style><img ...>` breakout inside the comment; the fixed "
                "behavior escapes the comment payload. A sanity probe confirms "
                "default comment stripping still removes comments."
            ),
            repro_setup=[],
            repro_cmd=["probe_mutation_xss_comments"],
            buggy_reply="BLEACH_MUTATION_XSS_RAW_COMMENT",
            fixed_marker="BLEACH_MUTATION_XSS_COMMENT_ESCAPED",
            sanity_cmd=["probe_default_strip_comments"],
            sanity_expected="BLEACH_DEFAULT_COMMENTS_STRIPPED",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_mutation_xss_comment_escape.diff"
            ),
            files_touched=["bleach/html5lib_shim.py", "bleach/sanitizer.py"],
        ),
    }
