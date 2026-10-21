# PR: Fix #verify_none_default: Require explicit algorithms to verify unsigned none JWTs

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around auth header credential boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `verify.js`.

Testing:
- `probe_verify_none_default` reaches `JWT_NONE_DEFAULT_REJECTED`.
- `probe_verify_hs256` still reaches `JWT_HS256_VALID`.
