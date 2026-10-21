# Issue #session_refresh_vary_cookie: Set Vary: Cookie when refreshing permanent session cookies

**Affected version:** flask 2.2.4

## Description
Flask before 2.2.5 and 2.3.2 can refresh a permanent session cookie without adding `Vary: Cookie` when the request does not access or modify the session. Behind a caching proxy, a cacheable response with `Set-Cookie` but without `Vary: Cookie` can disclose one client's session cookie to other clients if the proxy caches cookies.

Real upstream source: GHSA-m2qf-hxjv-5gpq / CVE-2023-30861.
Affected ranges: `<2.2.5` and `>=2.3.0,<2.3.2`.
Baseline: `2.2.4`.
Fixed versions: `2.2.5`, `2.3.2`.

The local probe uses Flask's test client. It first creates a permanent session, then requests a route that does not touch the session. The buggy behavior refreshes `Set-Cookie` without `Vary: Cookie`; the fixed behavior emits both. A separate sanity probe confirms routes that access the session still emit `Vary: Cookie`.
