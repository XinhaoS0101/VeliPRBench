# PR: Fix #append_empty: APPEND of empty string to non-existent key creates the key

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `redis` `7.0.15`.
- Touched issue path: `src/t_string.c`.
- Added benign fixture: `tests/hard-negative/append_empty-negative-cases.txt`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `EXISTS appk` reaches `0`.
- `APPEND appk2 hello` still reaches `5`.
