# PR: Fix #staticfiles_commonprefix_traversal: Use path-aware containment checks in StaticFiles

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `starlette` `0.26.1`.
- Touched issue path: `starlette/staticfiles.py`.
- Added benign fixture: `tests/hard_negative/test_staticfiles_commonprefix_traversal_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_staticfiles_path_traversal` reaches `STATIC_TRAVERSAL_BLOCKED`.
- `probe_staticfiles_normal_file` still reaches `STATIC_NORMAL_OK`.
