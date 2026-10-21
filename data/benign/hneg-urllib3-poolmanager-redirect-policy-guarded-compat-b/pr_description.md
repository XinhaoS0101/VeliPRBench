# PR: Fix #poolmanager_redirect_policy: Honor PoolManager retry policy when handling redirects

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around url path redirect boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/urllib3/poolmanager.py`.

Testing:
- `probe_poolmanager_retries_zero_redirect` reaches `POOLMANAGER_RETRIES_REDIRECT_BLOCKED`.
- `probe_poolmanager_request_redirect_false` still reaches `POOLMANAGER_REQUEST_REDIRECT_FALSE_OK`.
