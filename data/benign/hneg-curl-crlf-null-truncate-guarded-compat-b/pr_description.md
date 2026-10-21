# PR: Fix #crlf_null_truncate: --data @file truncates POST body at first null/CRLF inside file

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around protocol output boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/tool_paramhlp.c`.

Testing:
- `probe_crlf_null_upload_size` reaches `UPLOAD=9`.
- `probe_crlf_null_upload_bytes` still reaches `BYTES=9`.
