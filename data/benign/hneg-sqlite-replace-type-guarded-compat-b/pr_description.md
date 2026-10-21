# PR: Fix #replace_type: replace() with numeric input + empty pattern returns wrong type

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around parser resource boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/func.c`.

Testing:
- `SELECT typeof(replace(123, '', 'x'));` reaches `text`.
- `SELECT replace('foobar', 'bar', 'baz');` still reaches `foobaz`.
