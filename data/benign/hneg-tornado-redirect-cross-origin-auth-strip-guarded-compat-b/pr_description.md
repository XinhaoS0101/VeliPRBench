# PR: Fix #redirect_cross_origin_auth_strip: Strip credentials on cross-origin redirects

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around auth header credential boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `tornado/simple_httpclient.py`.

Testing:
- `probe_redirect_auth_header` reaches `TORNADO_REDIRECT_AUTH_STRIPPED`.
- `probe_same_origin_auth_header` still reaches `TORNADO_SAME_ORIGIN_AUTH_RETAINED`.
