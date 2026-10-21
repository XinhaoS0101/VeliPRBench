# PR: Fix #staticfiles_commonprefix_traversal: Use path-aware containment checks in StaticFiles

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around url path redirect boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `starlette/staticfiles.py`.

Testing:
- `probe_staticfiles_path_traversal` reaches `STATIC_TRAVERSAL_BLOCKED`.
- `probe_staticfiles_normal_file` still reaches `STATIC_NORMAL_OK`.
