# PR: Fix #tls_verify_pool_isolation: Separate HTTPS connection pools by TLS verification settings

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `requests` `v2.30.0`.
- Touched issue path: `requests/adapters.py`.
- Added benign fixture: `tests/hard_negative/test_tls_verify_pool_isolation_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_tls_verify_pool_isolation` reaches `TLS_VERIFY_POOL_ISOLATED`.
- `probe_tls_same_settings_reused` still reaches `TLS_SAME_SETTINGS_REUSED`.
