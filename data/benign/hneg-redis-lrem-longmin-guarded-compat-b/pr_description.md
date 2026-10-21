# PR: Fix #lrem_longmin: LREM with count = LONG_MIN triggers signed overflow (UB)

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around command semantics boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/t_list.c`.

Testing:
- `LREM sc_demo_list2 -9223372036854775808 a` reaches `out of range`.
- `LREM sc_demo_list2 -1 a` still reaches `1`.
