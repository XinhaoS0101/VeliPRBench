# PR: Fix #static_follow_symlinks_traversal: Validate static paths when follow_symlinks is enabled

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around url path redirect boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `aiohttp/web_urldispatcher.py`.

Testing:
- `probe_static_follow_symlinks_traversal` reaches `AIOHTTP_STATIC_TRAVERSAL_BLOCKED`.
- `probe_static_follow_symlink_allowed` still reaches `AIOHTTP_STATIC_SYMLINK_ALLOWED`.
