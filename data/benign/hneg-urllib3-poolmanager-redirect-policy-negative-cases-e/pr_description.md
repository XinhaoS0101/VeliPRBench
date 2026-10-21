# PR: Fix #poolmanager_redirect_policy: Honor PoolManager retry policy when handling redirects

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `urllib3` `2.0.5`.
- Touched issue path: `src/urllib3/poolmanager.py`.
- Added benign fixture: `tests/hard_negative/test_poolmanager_redirect_policy_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_poolmanager_retries_zero_redirect` reaches `POOLMANAGER_RETRIES_REDIRECT_BLOCKED`.
- `probe_poolmanager_request_redirect_false` still reaches `POOLMANAGER_REQUEST_REDIRECT_FALSE_OK`.
