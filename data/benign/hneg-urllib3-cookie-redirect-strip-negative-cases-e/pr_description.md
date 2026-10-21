# PR: Fix #cookie_redirect_strip: Strip Cookie header during cross-origin redirects

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `urllib3` `2.0.5`.
- Touched issue path: `src/urllib3/util/retry.py`.
- Added benign fixture: `tests/hard_negative/test_cookie_redirect_strip_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_cookie_redirect_header` reaches `COOKIE_REDIRECT_STRIPPED`.
- `probe_cookie_same_host_redirect` still reaches `COOKIE_SAME_HOST_RETAINED`.
