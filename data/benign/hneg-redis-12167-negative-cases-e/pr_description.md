# PR: Fix #12167: LPOS with RANK = LONG_MIN returns a wrong result (signed overflow)

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `redis` `7.0.15`.
- Touched issue path: `src/t_list.c`.
- Added benign fixture: `tests/hard-negative/12167-negative-cases.txt`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `LPOS sc_demo_list a RANK -9223372036854775808` reaches `out of range`.
- `LPOS sc_demo_list a RANK -1` still reaches `6`.
