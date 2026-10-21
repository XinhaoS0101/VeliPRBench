# Issue #sandbox_attr_filter_format: Route the attr filter through sandboxed attribute access

**Affected version:** jinja 3.1.2

## Description
Jinja 3.1.2 lets the `attr` filter return a raw `str.format` or `str.format_map` bound method from a sandboxed environment. Code that calls that returned formatter outside the sandbox can bypass Jinja's sandboxed formatter checks and access unsafe attributes such as `__class__` through format fields.

Real upstream source: GHSA-cpwx-vrp4-4pq7 / CVE-2025-27516.
Baseline: `3.1.2`.
Fixed version: `3.1.6`.

The local probe obtains `str.format` through the sandboxed `attr` filter and calls it directly with a dunder field. The fixed behavior is to return a sandbox-wrapped formatter that blocks unsafe fields; normal safe format fields must still work.
