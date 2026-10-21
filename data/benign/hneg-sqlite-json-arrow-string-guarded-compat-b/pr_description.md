# PR: Fix #json_arrow_string: JSON -> / ->> operators treat string-as-number key as array index

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around parser resource boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/json.c`.

Testing:
- `SELECT '{"42":"alice"}' ->> '42';` reaches `alice`.
- `SELECT '[1,2,3,4,5]' ->> 2;` still reaches `3`.
