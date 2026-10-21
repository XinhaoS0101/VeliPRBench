# PR: Fix #apply_symlink_escape: Block git apply writes through newly renamed symlinks

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around security sensitive maintenance boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `apply.c`.

Testing:
- `probe_apply_symlink_escape` reaches `GIT_APPLY_SYMLINK_BLOCKED`.
- `probe_apply_normal_create` still reaches `GIT_APPLY_NORMAL_CREATE_OK`.
