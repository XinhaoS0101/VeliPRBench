# Issue #mutation_xss_comment_escape: Escape HTML comments in mutation-XSS sanitizer contexts

**Affected version:** bleach v3.2.3

## Description
Bleach before 3.3.0 could preserve raw HTML comments when `bleach.clean` was called with `strip_comments=False` and specific SVG/MathML/raw-text tag allowlists. Browser reparsing could mutate the sanitized output and expose attacker-controlled tags such as `<img onerror=...>`.

Real upstream source: GHSA-vv2x-vrpj-qqpq / CVE-2021-23980.
Affected range: `<3.3.0`.
Baseline: `v3.2.3`.
Fixed version: `3.3.0`.

The local probe calls `bleach.clean` with the advisory conditions: `svg` or `math`, `p`, a raw-text-like tag, and `strip_comments=False`. The buggy behavior preserves a raw `</style><img ...>` breakout inside the comment; the fixed behavior escapes the comment payload. A sanity probe confirms default comment stripping still removes comments.
