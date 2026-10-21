# Issue #proxy_auth_https: Do not leak Proxy-Authorization on HTTPS tunneled requests

**Affected version:** requests v2.30.0

## Description
Requests before 2.31.0 could attach a `Proxy-Authorization` header directly to an HTTPS destination request when rebuilding proxy settings across redirects. In standard adapter flows, urllib3 handles proxy credentials for CONNECT tunnels, so Requests should not place proxy credentials on TLS-tunneled requests where the destination server may observe them.

Real upstream source: GHSA-j8r2-6x86-q33q / CVE-2023-32681.
Affected range: `>=2.3.0,<2.31.0`.
Baseline: `v2.30.0`.
Fixed version: `2.31.0`.

Local reproduction uses `Session.rebuild_proxies()` directly: for an HTTPS prepared request and an authenticated proxy, the fixed code must leave `Proxy-Authorization` absent. A separate HTTP sanity probe confirms proxy auth is still attached for plain HTTP requests.
