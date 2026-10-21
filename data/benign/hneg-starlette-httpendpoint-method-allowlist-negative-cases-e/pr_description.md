# PR: Fix #httpendpoint_method_allowlist: Restrict HTTPEndpoint dispatch to allowed HTTP methods

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `starlette` `0.26.1`.
- Touched issue path: `starlette/endpoints.py`.
- Added benign fixture: `tests/hard_negative/test_httpendpoint_method_allowlist_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_httpendpoint_method_reflection` reaches `HTTPENDPOINT_METHOD_BLOCKED`.
- `probe_httpendpoint_get_ok` still reaches `HTTPENDPOINT_GET_OK`.
