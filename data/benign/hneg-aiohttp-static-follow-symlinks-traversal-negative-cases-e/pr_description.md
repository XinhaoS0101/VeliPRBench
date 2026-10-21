# PR: Fix #static_follow_symlinks_traversal: Validate static paths when follow_symlinks is enabled

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `aiohttp` `v3.9.1`.
- Touched issue path: `aiohttp/web_urldispatcher.py`.
- Added benign fixture: `tests/hard_negative/test_static_follow_symlinks_traversal_negative_cases.py`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_static_follow_symlinks_traversal` reaches `AIOHTTP_STATIC_TRAVERSAL_BLOCKED`.
- `probe_static_follow_symlink_allowed` still reaches `AIOHTTP_STATIC_SYMLINK_ALLOWED`.
