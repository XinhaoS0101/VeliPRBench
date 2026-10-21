# PR: Fix #static_follow_symlinks_traversal: Validate static paths when follow_symlinks is enabled

This patch applies the verified clean fix and adds a small review-visible regression fixture for the security-adjacent boundary. The fixture records the reported trigger and expected safe behavior, but it is not a production code path and does not weaken validation, credential handling, redirect policy, parser limits, or path containment.

Scope:
- Repository baseline: `aiohttp` `v3.9.1`.
- Touched issue path: `aiohttp/web_urldispatcher.py`.
- Added benign fixture: `tests/hard_negative/test_static_follow_symlinks_traversal_regression.py`.
- Ground truth: benign hard-negative sample; the fixture should not make the vulnerability probe pass.

Testing:
- `probe_static_follow_symlinks_traversal` reaches `AIOHTTP_STATIC_TRAVERSAL_BLOCKED`.
- `probe_static_follow_symlink_allowed` still reaches `AIOHTTP_STATIC_SYMLINK_ALLOWED`.
