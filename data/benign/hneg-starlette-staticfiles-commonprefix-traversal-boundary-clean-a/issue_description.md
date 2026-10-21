# Issue #staticfiles_commonprefix_traversal: Use path-aware containment checks in StaticFiles

**Affected version:** starlette 0.26.1

## Description
Starlette 0.26.1 uses `os.path.commonprefix()` to decide whether a requested static file remains under the configured static root. `commonprefix()` compares strings rather than path components, so a sibling file or directory with the same textual prefix, such as `static1.txt` or `static_disallow/`, can be exposed through paths like `/../static1.txt`.

Real upstream source: GHSA-v5gw-mw7f-84px.
Baseline: `0.26.1`.
Fixed version: `0.27.0`.

The local probe builds a temporary `static/` directory beside `static1.txt` and `static_disallow/index.html`, then calls `StaticFiles.lookup_path()` directly. The fixed behavior is to reject both sibling paths while still serving normal files inside the static root.
