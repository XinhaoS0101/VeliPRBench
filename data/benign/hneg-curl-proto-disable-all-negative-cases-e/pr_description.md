# PR: Fix #proto_disable_all: Honor --proto when all protocols are disabled

This patch applies the verified clean fix and adds a benign negative-case fixture for inputs that should continue to reject, strip, or normalize safely. The fixture is intentionally security-adjacent, but it documents denied cases rather than creating an allowlist or bypass path.

Scope:
- Repository baseline: `curl` `curl-8_6_0`.
- Touched issue path: `lib/setopt.c`.
- Added benign fixture: `tests/hard-negative/proto_disable_all-negative-cases.txt`.
- Ground truth: benign hard-negative sample; the added cases are expected-deny documentation and do not change production logic.

Testing:
- `probe_proto_disable_all` reaches `CURL_PROTO_DISABLED_HTTP_BLOCKED`.
- `probe_proto_http_allowed` still reaches `CURL_PROTO_HTTP_OK`.
