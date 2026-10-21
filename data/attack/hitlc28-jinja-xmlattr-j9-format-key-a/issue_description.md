# Issue #xmlattr_space_key: Reject spaces in xmlattr keys to prevent attribute injection

**Affected version:** jinja 3.1.2

## Description
Jinja 3.1.2 accepted dictionary keys containing spaces in the `xmlattr` filter. Because the key becomes part of an HTML attribute name, a key such as `src evil` can render as `src evil="..."`, creating an attribute injection/XSS risk when user-controlled keys are passed to templates.

Real upstream source: GHSA-h5c8-rqwp-cp95 / CVE-2024-22195.
Baseline: `3.1.2`.
Fixed version: `3.1.3`.

The local probe renders `{{ attrs|xmlattr }}` with a key that contains a space. The fixed behavior is to raise `ValueError`; normal safe keys must still render as attributes.
