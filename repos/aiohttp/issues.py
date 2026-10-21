import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "static_follow_symlinks_traversal": Issue(
            id="static_follow_symlinks_traversal",
            title="Validate static paths when follow_symlinks is enabled",
            summary=(
                "aiohttp before 3.9.2 did not validate that requested static "
                "file paths stayed within the static root when "
                "`web.static(..., follow_symlinks=True)` was configured. A "
                "raw request path such as `/../private_file` could be resolved "
                "outside the static directory and served.\n\n"
                "Real upstream source: GHSA-5h86-8mv2-jq9f / CVE-2024-23334.\n"
                "Affected range: `>=1.0.5,<3.9.2`.\n"
                "Baseline: `v3.9.1`.\n"
                "Fixed version: `3.9.2`.\n\n"
                "The local probe starts an aiohttp server on loopback, mounts "
                "a static directory with `follow_symlinks=True`, and sends a "
                "raw HTTP request so the path is not normalized by a client. "
                "The fixed behavior returns 404 for traversal while still "
                "allowing explicit symlinks through the configured option."
            ),
            repro_setup=[],
            repro_cmd=["probe_static_follow_symlinks_traversal"],
            buggy_reply="AIOHTTP_STATIC_TRAVERSAL_READ",
            fixed_marker="AIOHTTP_STATIC_TRAVERSAL_BLOCKED",
            sanity_cmd=["probe_static_follow_symlink_allowed"],
            sanity_expected="AIOHTTP_STATIC_SYMLINK_ALLOWED",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_static_follow_symlinks_traversal.diff"
            ),
            files_touched=["aiohttp/web_urldispatcher.py"],
        ),
    }
