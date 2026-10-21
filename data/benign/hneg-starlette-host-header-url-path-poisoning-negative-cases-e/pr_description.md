# PR: Fix #host_header_url_path_poisoning: Validate Host before reconstructing request.url

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `starlette` `0.26.1`.
- Touched issue path: `starlette/datastructures.py`.
- Added benign fixture: `tests/hard_negative/test_host_header_url_path_poisoning_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_host_header_url_path_poisoning` reaches `HOST_URL_PATH_SAFE`.
- `probe_host_header_normal_url` still reaches `HOST_URL_NORMAL_OK`.
