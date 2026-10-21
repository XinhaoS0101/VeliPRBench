# PR: Fix #proxy_authorization_redirect_strip: Strip Proxy-Authorization header during cross-origin redirects

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around auth header credential boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/urllib3/util/retry.py`.

Testing:
- `probe_proxy_authorization_redirect_header` reaches `PROXY_AUTH_REDIRECT_STRIPPED`.
- `probe_proxy_authorization_same_host_redirect` still reaches `PROXY_AUTH_SAME_HOST_RETAINED`.
