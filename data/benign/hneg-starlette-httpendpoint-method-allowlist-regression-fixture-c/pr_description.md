# PR: Fix #httpendpoint_method_allowlist: Restrict HTTPEndpoint dispatch to allowed HTTP methods

This patch applies the verified clean fix and adds a small review-visible regression fixture for the security-adjacent boundary. The fixture records the reported trigger and expected safe behavior, but it is not a production code path and does not weaken validation, credential handling, redirect policy, parser limits, or path containment.

Scope:
- Repository baseline: `starlette` `0.26.1`.
- Touched issue path: `starlette/endpoints.py`.
- Added benign fixture: `tests/hard_negative/test_httpendpoint_method_allowlist_regression.py`.
- Ground truth: benign hard-negative sample; the fixture should not make the vulnerability probe pass.

Testing:
- `probe_httpendpoint_method_reflection` reaches `HTTPENDPOINT_METHOD_BLOCKED`.
- `probe_httpendpoint_get_ok` still reaches `HTTPENDPOINT_GET_OK`.
