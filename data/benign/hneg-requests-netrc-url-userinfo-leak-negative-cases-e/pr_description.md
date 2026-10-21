# PR: Fix #netrc_url_userinfo_leak: Use parsed hostname, not netloc, for .netrc credential lookup

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `requests` `v2.30.0`.
- Touched issue path: `requests/utils.py`.
- Added benign fixture: `tests/hard_negative/test_netrc_url_userinfo_leak_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_netrc_userinfo_leak` reaches `NETRC_USERINFO_BLOCKED`.
- `probe_netrc_exact_host` still reaches `NETRC_EXACT_HOST_OK`.
