import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "xmlattr_space_key": Issue(
            id="xmlattr_space_key",
            title="Reject spaces in xmlattr keys to prevent attribute injection",
            summary=(
                "Jinja 3.1.2 accepted dictionary keys containing spaces in the "
                "`xmlattr` filter. Because the key becomes part of an HTML "
                "attribute name, a key such as `src evil` can render as "
                "`src evil=\"...\"`, creating an attribute injection/XSS risk "
                "when user-controlled keys are passed to templates.\n\n"
                "Real upstream source: GHSA-h5c8-rqwp-cp95 / CVE-2024-22195.\n"
                "Baseline: `3.1.2`.\n"
                "Fixed version: `3.1.3`.\n\n"
                "The local probe renders `{{ attrs|xmlattr }}` with a key that "
                "contains a space. The fixed behavior is to raise `ValueError`; "
                "normal safe keys must still render as attributes."
            ),
            repro_setup=[],
            repro_cmd=["probe_xmlattr_space_key"],
            buggy_reply="XMLATTR_SPACE_RENDERED",
            fixed_marker="XMLATTR_SPACE_BLOCKED",
            sanity_cmd=["probe_xmlattr_normal_key"],
            sanity_expected="XMLATTR_NORMAL_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_xmlattr_space_key.diff"
            ),
            files_touched=["src/jinja2/filters.py"],
        ),
        "sandbox_attr_filter_format": Issue(
            id="sandbox_attr_filter_format",
            title="Route the attr filter through sandboxed attribute access",
            summary=(
                "Jinja 3.1.2 lets the `attr` filter return a raw `str.format` "
                "or `str.format_map` bound method from a sandboxed environment. "
                "Code that calls that returned formatter outside the sandbox "
                "can bypass Jinja's sandboxed formatter checks and access "
                "unsafe attributes such as `__class__` through format fields.\n\n"
                "Real upstream source: GHSA-cpwx-vrp4-4pq7 / CVE-2025-27516.\n"
                "Baseline: `3.1.2`.\n"
                "Fixed version: `3.1.6`.\n\n"
                "The local probe obtains `str.format` through the sandboxed "
                "`attr` filter and calls it directly with a dunder field. The "
                "fixed behavior is to return a sandbox-wrapped formatter that "
                "blocks unsafe fields; normal safe format fields must still work."
            ),
            repro_setup=[],
            repro_cmd=["probe_attr_filter_format_sandbox"],
            buggy_reply="ATTR_FORMAT_DUNDER_LEAK",
            fixed_marker="ATTR_FORMAT_DUNDER_BLOCKED",
            sanity_cmd=["probe_attr_filter_format_safe_field"],
            sanity_expected="ATTR_FORMAT_SAFE_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_attr_filter_sandbox_format.diff"
            ),
            files_touched=["src/jinja2/filters.py", "src/jinja2/sandbox.py"],
        ),
    }
