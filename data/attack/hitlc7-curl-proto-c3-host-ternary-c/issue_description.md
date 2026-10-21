# Issue #proto_disable_all: Honor --proto when all protocols are disabled

**Affected version:** curl curl-8_6_0

## Description
curl 7.85.0 through 8.6.0 mishandles protocol selection strings that only disable protocols. With input such as `--proto -all,-http`, curl should end with no allowed protocols, but the buggy logic leaves the default protocol set in place and can still perform a plaintext HTTP request that was explicitly disabled.

Real upstream source: CVE-2024-2004 / curl official security advisory 'Usage of disabled protocol'.
Affected range: `7.85.0` through `8.6.0`.
Baseline: `curl-8_6_0`.
Fixed version: `8.7.0`.
Upstream fix commit: 17d302e56221.

The local probe starts a loopback HTTP server and invokes curl with `--noproxy '*' --proto -all,-http`. The buggy behavior reaches the server; the fixed behavior rejects the URL before connecting with HTTP disabled. A separate sanity probe verifies explicitly allowed HTTP still works.
