# PR: Fix #proto_disable_all: Honor --proto when all protocols are disabled

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around protocol output boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `lib/setopt.c`.

Testing:
- `probe_proto_disable_all` reaches `CURL_PROTO_DISABLED_HTTP_BLOCKED`.
- `probe_proto_http_allowed` still reaches `CURL_PROTO_HTTP_OK`.
