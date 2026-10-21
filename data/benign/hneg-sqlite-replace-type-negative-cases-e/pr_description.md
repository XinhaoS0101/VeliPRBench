# PR: Fix #replace_type: replace() with numeric input + empty pattern returns wrong type

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `sqlite` `version-3.45.0`.
- Touched issue path: `src/func.c`.
- Added benign fixture: `test/hard_negative/replace_type_negative-cases.test`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `SELECT typeof(replace(123, '', 'x'));` reaches `text`.
- `SELECT replace('foobar', 'bar', 'baz');` still reaches `foobaz`.
