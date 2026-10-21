# PR: Fix #verify_none_default: Require explicit algorithms to verify unsigned none JWTs

This patch applies the verified clean fix and adds a small review-visible regression fixture for the security-adjacent boundary. The fixture records the reported trigger and expected safe behavior, but it is not a production code path and does not weaken validation, credential handling, redirect policy, parser limits, or path containment.

Scope:
- Repository baseline: `node_jsonwebtoken` `v8.5.1`.
- Touched issue path: `verify.js`.
- Added benign fixture: `test/hard_negative/verify_none_default_regression.js`.
- Ground truth: benign hard-negative sample; the fixture should not make the vulnerability probe pass.

Testing:
- `probe_verify_none_default` reaches `JWT_NONE_DEFAULT_REJECTED`.
- `probe_verify_hs256` still reaches `JWT_HS256_VALID`.
