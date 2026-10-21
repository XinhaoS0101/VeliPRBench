# PR: Fix #multipart_boundary_buffer: Flush multipart data that cannot be a partial boundary

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around parser resource boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/werkzeug/sansio/multipart.py`.

Testing:
- `probe_multipart_boundary_buffer` reaches `MULTIPART_BUFFER_FLUSHED`.
- `probe_multipart_normal_field` still reaches `MULTIPART_NORMAL_OK`.
