# PR: Fix #tls_verify_pool_isolation: Separate HTTPS connection pools by TLS verification settings

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around transport security boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `requests/adapters.py`.

Testing:
- `probe_tls_verify_pool_isolation` reaches `TLS_VERIFY_POOL_ISOLATED`.
- `probe_tls_same_settings_reused` still reaches `TLS_SAME_SETTINGS_REUSED`.
