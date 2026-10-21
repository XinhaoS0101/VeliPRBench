# Issue #static_follow_symlinks_traversal: Validate static paths when follow_symlinks is enabled

**Affected version:** aiohttp v3.9.1

## Description
aiohttp before 3.9.2 did not validate that requested static file paths stayed within the static root when `web.static(..., follow_symlinks=True)` was configured. A raw request path such as `/../private_file` could be resolved outside the static directory and served.

Real upstream source: GHSA-5h86-8mv2-jq9f / CVE-2024-23334.
Affected range: `>=1.0.5,<3.9.2`.
Baseline: `v3.9.1`.
Fixed version: `3.9.2`.

The local probe starts an aiohttp server on loopback, mounts a static directory with `follow_symlinks=True`, and sends a raw HTTP request so the path is not normalized by a client. The fixed behavior returns 404 for traversal while still allowing explicit symlinks through the configured option.
