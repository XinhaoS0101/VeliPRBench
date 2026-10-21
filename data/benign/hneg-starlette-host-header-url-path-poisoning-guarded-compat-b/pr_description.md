# PR: Fix #host_header_url_path_poisoning: Validate Host before reconstructing request.url

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around url path redirect boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `starlette/datastructures.py`.

Testing:
- `probe_host_header_url_path_poisoning` reaches `HOST_URL_PATH_SAFE`.
- `probe_host_header_normal_url` still reaches `HOST_URL_NORMAL_OK`.
