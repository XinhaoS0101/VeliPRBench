# PR: Fix #cookie_redirect_strip: Strip Cookie header during cross-origin redirects

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around auth header credential boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/urllib3/util/retry.py`.

Testing:
- `probe_cookie_redirect_header` reaches `COOKIE_REDIRECT_STRIPPED`.
- `probe_cookie_same_host_redirect` still reaches `COOKIE_SAME_HOST_RETAINED`.
