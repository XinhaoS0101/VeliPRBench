# PR: Fix #append_empty: APPEND of empty string to non-existent key creates the key

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around command semantics boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/t_string.c`.

Testing:
- `EXISTS appk` reaches `0`.
- `APPEND appk2 hello` still reaches `5`.
