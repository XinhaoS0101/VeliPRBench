# Issue #cookie_redirect_strip: Strip Cookie header during cross-origin redirects

**Affected version:** urllib3 2.0.5

## Description
urllib3 2.0.5 strips `Authorization` on cross-origin redirects, but does not treat a user-supplied `Cookie` header as sensitive. When automatic redirects are enabled, a request that includes `Cookie` can leak that header to a different origin selected by the redirect target.

Real upstream source: GHSA-v845-jxx5-vc9f / CVE-2023-43804.
Baseline: `2.0.5`.
Fixed version: `2.0.6`.

The local probe starts two loopback HTTP servers. The first server redirects to the second server, which records request headers. The buggy behavior forwards `Cookie`; the fixed behavior strips both `Cookie` and `Authorization` on cross-origin redirects. Same-host redirects must still retain `Cookie`.
