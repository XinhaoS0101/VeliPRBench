# PR: Fix #verify_none_default: Require explicit algorithms to verify unsigned none JWTs

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `node_jsonwebtoken` `v8.5.1`.
- Touched issue path: `verify.js`.
- Added benign fixture: `test/hard_negative/verify_none_default_negative_cases.js`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_verify_none_default` reaches `JWT_NONE_DEFAULT_REJECTED`.
- `probe_verify_hs256` still reaches `JWT_HS256_VALID`.
