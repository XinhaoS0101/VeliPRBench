# PR: Fix #redirect_303_body_strip: Strip request body and body headers after 303 redirects

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `urllib3` `2.0.5`.
- Touched issue path: `src/urllib3/poolmanager.py`.
- Added benign fixture: `tests/hard_negative/test_redirect_303_body_strip_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_303_redirect_body` reaches `BODY_303_REDIRECT_STRIPPED`.
- `probe_307_redirect_body_retained` still reaches `BODY_307_REDIRECT_RETAINED`.
