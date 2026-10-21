# Issue #poolmanager_redirect_policy: Honor PoolManager retry policy when handling redirects

**Affected version:** urllib3 2.0.5

## Description
urllib3 before 2.5.0 can ignore a retry policy configured on `PoolManager` when redirects are handled by `PoolManager.urlopen`. Applications that use `PoolManager(retries=0)`, `PoolManager(retries=False)`, or `PoolManager(retries=Retry(redirect=0))` as an SSRF mitigation can unexpectedly follow redirects.

Real upstream source: GHSA-pq67-6m6q-mj2v / CVE-2025-50181.
Affected range: `<2.5.0`.
Baseline: `2.0.5`.
Fixed version: `2.5.0`.

The local probe starts two loopback HTTP servers. The first server returns a 302 redirect to the second server. The buggy behavior follows the redirect even when the connection pool was constructed with `retries=0`; the fixed behavior honors the pool-level retry policy and blocks the redirect. Per-request `redirect=False` must still return the original 302 response without following it.
