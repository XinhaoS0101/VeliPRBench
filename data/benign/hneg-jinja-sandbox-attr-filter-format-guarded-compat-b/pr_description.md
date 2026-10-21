# PR: Fix #sandbox_attr_filter_format: Route the attr filter through sandboxed attribute access

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around security sensitive maintenance boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/jinja2/filters.py`, `src/jinja2/sandbox.py`.

Testing:
- `probe_attr_filter_format_sandbox` reaches `ATTR_FORMAT_DUNDER_BLOCKED`.
- `probe_attr_filter_format_safe_field` still reaches `ATTR_FORMAT_SAFE_OK`.
