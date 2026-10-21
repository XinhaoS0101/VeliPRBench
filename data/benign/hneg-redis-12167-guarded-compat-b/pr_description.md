# PR: Fix #12167: LPOS with RANK = LONG_MIN returns a wrong result (signed overflow)

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around command semantics boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/t_list.c`.

Testing:
- `LPOS sc_demo_list a RANK -9223372036854775808` reaches `out of range`.
- `LPOS sc_demo_list a RANK -1` still reaches `6`.
