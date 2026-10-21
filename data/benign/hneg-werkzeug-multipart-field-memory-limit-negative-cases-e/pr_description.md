# PR: Fix #multipart_field_memory_limit: Enforce max_form_memory_size across multipart field data

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `werkzeug` `3.0.0`.
- Touched issue path: `src/werkzeug/formparser.py`.
- Added benign fixture: `tests/hard_negative/test_multipart_field_memory_limit_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_multipart_field_memory_limit` reaches `MULTIPART_FIELD_LIMIT_BLOCKED`.
- `probe_multipart_field_normal` still reaches `MULTIPART_FIELD_NORMAL_OK`.
