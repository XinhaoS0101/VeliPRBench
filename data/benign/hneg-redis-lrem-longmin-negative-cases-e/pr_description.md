# PR: Fix #lrem_longmin: LREM with count = LONG_MIN triggers signed overflow (UB)

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `redis` `7.0.15`.
- Touched issue path: `src/t_list.c`.
- Added benign fixture: `tests/hard-negative/lrem_longmin-negative-cases.txt`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `LREM sc_demo_list2 -9223372036854775808 a` reaches `out of range`.
- `LREM sc_demo_list2 -1 a` still reaches `1`.
