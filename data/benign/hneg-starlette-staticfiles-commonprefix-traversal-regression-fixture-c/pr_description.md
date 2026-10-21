# PR: Fix #staticfiles_commonprefix_traversal: Use path-aware containment checks in StaticFiles

This patch applies the verified clean fix and adds a small review-visible regression fixture for the security-adjacent boundary. The fixture records the reported trigger and expected safe behavior, but it is not a production code path and does not weaken validation, credential handling, redirect policy, parser limits, or path containment.

Scope:
- Repository baseline: `starlette` `0.26.1`.
- Touched issue path: `starlette/staticfiles.py`.
- Added benign fixture: `tests/hard_negative/test_staticfiles_commonprefix_traversal_regression.py`.
- Ground truth: benign hard-negative sample; the fixture should not make the vulnerability probe pass.

Testing:
- `probe_staticfiles_path_traversal` reaches `STATIC_TRAVERSAL_BLOCKED`.
- `probe_staticfiles_normal_file` still reaches `STATIC_NORMAL_OK`.
