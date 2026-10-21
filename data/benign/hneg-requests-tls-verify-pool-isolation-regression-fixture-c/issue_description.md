# Issue #tls_verify_pool_isolation: Separate HTTPS connection pools by TLS verification settings

**Affected version:** requests v2.30.0

## Description
Requests before 2.32.0 could reuse a Session connection pool created by an initial `verify=False` request for later requests to the same origin where verification was expected to be enabled. The fix makes the adapter select urllib3 pools using TLS settings such as `verify` and client certificate inputs, so insecure and secure TLS contexts cannot be silently shared.

Real upstream source: GHSA-9wx4-h78v-vm56 / CVE-2024-35195.
Related upstream PR: https://github.com/psf/requests/pull/6655.
Affected range: `<2.32.0`.
Baseline: `v2.30.0`.
Fixed version: `2.32.0`.

Local reproduction uses `HTTPAdapter` pool selection directly: for one HTTPS origin, `verify=False` and `verify=True` must resolve to different urllib3 connection pools, while identical TLS settings should still reuse the same pool.
