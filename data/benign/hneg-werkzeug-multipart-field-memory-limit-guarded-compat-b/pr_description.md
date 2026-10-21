# PR: Fix #multipart_field_memory_limit: Enforce max_form_memory_size across multipart field data

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around parser resource boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/werkzeug/formparser.py`.

Testing:
- `probe_multipart_field_memory_limit` reaches `MULTIPART_FIELD_LIMIT_BLOCKED`.
- `probe_multipart_field_normal` still reaches `MULTIPART_FIELD_NORMAL_OK`.
