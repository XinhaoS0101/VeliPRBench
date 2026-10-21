# Issue #redirect_cross_origin_auth_strip: Strip credentials on cross-origin redirects

**Affected version:** tornado v6.5.5

## Description
Tornado before 6.5.6 did not clear authentication material when SimpleAsyncHTTPClient followed a redirect to a different scheme, host, or port. The redirected request could forward `Authorization`, `Cookie`, or HTTP auth credentials to the new origin.

Real upstream source: GHSA-3x9g-8vmp-wqvf / CVE-2026-49853.
Affected range: `<6.5.6`.
Baseline: `v6.5.5`.
Fixed version: `6.5.6`.

The local probe starts two Tornado HTTP servers on loopback: one returns a redirect, and the second records headers on the redirected request. The fixed behavior strips credentials for cross-origin redirects while retaining them for same-origin redirects.
