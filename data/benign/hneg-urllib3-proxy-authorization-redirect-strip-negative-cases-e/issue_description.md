# Issue #proxy_authorization_redirect_strip: Strip Proxy-Authorization header during cross-origin redirects

**Affected version:** urllib3 2.0.5

## Description
urllib3 before 2.2.2 stripped `Authorization` on cross-origin redirects, but did not strip a user-supplied `Proxy-Authorization` header. Applications that set this header manually and follow redirects could leak proxy credentials to a different origin selected by the redirect target.

Real upstream source: GHSA-34jh-p97f-mpxf / CVE-2024-37891.
Affected range: `<=2.2.1`.
Baseline: `2.0.5`.
Fixed version: `2.2.2`.

The local probe starts two loopback HTTP servers. The first server redirects to the second server, which records request headers. The fixed behavior strips both `Authorization` and `Proxy-Authorization` on cross-origin redirects. Same-host redirects must still retain the header.
