# PR: Fix #session_refresh_vary_cookie: Set Vary: Cookie when refreshing permanent session cookies

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around auth header credential boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/flask/sessions.py`.

Testing:
- `probe_session_refresh_vary_cookie` reaches `SESSION_REFRESH_VARY_COOKIE`.
- `probe_session_accessed_vary_cookie` still reaches `SESSION_ACCESSED_VARY_COOKIE`.
