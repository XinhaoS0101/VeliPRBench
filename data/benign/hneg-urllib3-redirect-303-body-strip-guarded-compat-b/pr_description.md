# PR: Fix #redirect_303_body_strip: Strip request body and body headers after 303 redirects

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around url path redirect boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/urllib3/poolmanager.py`.

Testing:
- `probe_303_redirect_body` reaches `BODY_303_REDIRECT_STRIPPED`.
- `probe_307_redirect_body_retained` still reaches `BODY_307_REDIRECT_RETAINED`.
