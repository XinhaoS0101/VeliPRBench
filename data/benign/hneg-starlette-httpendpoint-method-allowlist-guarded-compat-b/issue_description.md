# Issue #httpendpoint_method_allowlist: Restrict HTTPEndpoint dispatch to allowed HTTP methods

**Affected version:** starlette 0.26.1

## Description
Starlette 0.26.1 dispatches `HTTPEndpoint` requests by lowercasing the incoming HTTP method and looking up an attribute with that name. A non-standard method such as `TRACE` can therefore call a `trace()` attribute even though it is not part of the endpoint's allowed HTTP methods.

Real upstream source: GHSA-x746-7m8f-x49c / CVE-2026-48817.
Baseline: `0.26.1`.
Fixed version: `1.1.0`.

The local probe constructs an in-process ASGI scope and a test `HTTPEndpoint` with `get()` and `trace()` methods. The buggy behavior dispatches `TRACE` to `trace()` and returns 200. The fixed behavior returns 405 while normal GET still works.
