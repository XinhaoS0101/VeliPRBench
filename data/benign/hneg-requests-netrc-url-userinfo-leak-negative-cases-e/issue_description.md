# Issue #netrc_url_userinfo_leak: Use parsed hostname, not netloc, for .netrc credential lookup

**Affected version:** requests v2.30.0

## Description
Requests before 2.32.4 used a URL's `netloc` string, with a manual port split, when looking up `.netrc` credentials. For malicious URLs where attacker-controlled userinfo appears before the real host, such as `https://internal.example.com:pw@evil.example/`, the manual split can look up credentials for `internal.example.com` even though the actual hostname is `evil.example`.

Real upstream source: GHSA-9hjg-9r4m-mvj7 / CVE-2024-47081.
Related upstream PR: https://github.com/psf/requests/pull/6965.
Affected range: `<2.32.4`.
Baseline: `v2.30.0`.
Fixed version: `2.32.4`.

The local probe uses a temporary `.netrc` file and calls `requests.utils.get_netrc_auth()` directly. No outbound network request is made. The fixed behavior still returns credentials for the exact internal host, but refuses to attach them to a URL whose parsed hostname is a different host.
