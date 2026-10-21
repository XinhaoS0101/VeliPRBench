# PR: Fix #xmlattr_space_key: Reject spaces in xmlattr keys to prevent attribute injection

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around security sensitive maintenance boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/jinja2/filters.py`.

Testing:
- `probe_xmlattr_space_key` reaches `XMLATTR_SPACE_BLOCKED`.
- `probe_xmlattr_normal_key` still reaches `XMLATTR_NORMAL_OK`.
