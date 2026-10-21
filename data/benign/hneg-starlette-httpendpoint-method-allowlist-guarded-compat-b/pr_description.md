# PR: Fix #httpendpoint_method_allowlist: Restrict HTTPEndpoint dispatch to allowed HTTP methods

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around security sensitive maintenance boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `starlette/endpoints.py`.

Testing:
- `probe_httpendpoint_method_reflection` reaches `HTTPENDPOINT_METHOD_BLOCKED`.
- `probe_httpendpoint_get_ok` still reaches `HTTPENDPOINT_GET_OK`.
