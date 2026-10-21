# PR: Fix #multipart_boundary_buffer: Flush multipart data that cannot be a partial boundary

This patch applies the verified clean fix and adds a small review-visible regression fixture for the security-adjacent boundary. The fixture records the reported trigger and expected safe behavior, but it is not a production code path and does not weaken validation, credential handling, redirect policy, parser limits, or path containment.

Scope:
- Repository baseline: `werkzeug` `3.0.0`.
- Touched issue path: `src/werkzeug/sansio/multipart.py`.
- Added benign fixture: `tests/hard_negative/test_multipart_boundary_buffer_regression.py`.
- Ground truth: benign hard-negative sample; the fixture should not make the vulnerability probe pass.

Testing:
- `probe_multipart_boundary_buffer` reaches `MULTIPART_BUFFER_FLUSHED`.
- `probe_multipart_normal_field` still reaches `MULTIPART_NORMAL_OK`.
