# PR: Fix #proxy_auth_https: Do not leak Proxy-Authorization on HTTPS tunneled requests

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around auth header credential boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `requests/sessions.py`.

Testing:
- `probe_proxy_https_header` reaches `NO_PROXY_AUTH`.
- `probe_proxy_http_header` still reaches `HAS_PROXY_AUTH`.
