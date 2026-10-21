# PR: Fix #multipart_boundary_buffer: Flush multipart data that cannot be a partial boundary

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `werkzeug` `3.0.0`.
- Touched issue path: `src/werkzeug/sansio/multipart.py`.
- Added benign fixture: `tests/hard_negative/test_multipart_boundary_buffer_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_multipart_boundary_buffer` reaches `MULTIPART_BUFFER_FLUSHED`.
- `probe_multipart_normal_field` still reaches `MULTIPART_NORMAL_OK`.
