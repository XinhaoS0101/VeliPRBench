# Issue #host_header_url_path_poisoning: Validate Host before reconstructing request.url

**Affected version:** starlette 0.26.1

## Description
Starlette versions through 1.0.0 reconstructed `request.url` by concatenating the raw HTTP `Host` header with the ASGI path and then parsing the combined string. A malformed Host header containing path/query delimiters such as `/`, `?`, or `#` can therefore make `request.url.path` differ from the actual `scope['path']` used for routing. Middleware or endpoint code that makes security decisions from `request.url.path` can see the wrong path.

Real upstream source: GHSA-86qp-5c8j-p5mr / CVE-2026-48710.
Affected range: `<=1.0.0`.
Baseline: `0.26.1`.
Fixed version: `1.0.1`.

The local probe constructs an in-process ASGI scope with a malformed Host header and calls `URL(scope=...)` directly. The fixed behavior rejects the malformed Host for URL reconstruction, falls back to the ASGI server tuple, and keeps `url.path` equal to the real request path. A separate sanity probe verifies normal Host headers still drive URL reconstruction.
