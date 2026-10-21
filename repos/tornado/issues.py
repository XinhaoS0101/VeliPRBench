import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "redirect_cross_origin_auth_strip": Issue(
            id="redirect_cross_origin_auth_strip",
            title="Strip credentials on cross-origin redirects",
            summary=(
                "Tornado before 6.5.6 did not clear authentication material "
                "when SimpleAsyncHTTPClient followed a redirect to a different "
                "scheme, host, or port. The redirected request could forward "
                "`Authorization`, `Cookie`, or HTTP auth credentials to the "
                "new origin.\n\n"
                "Real upstream source: GHSA-3x9g-8vmp-wqvf / CVE-2026-49853.\n"
                "Affected range: `<6.5.6`.\n"
                "Baseline: `v6.5.5`.\n"
                "Fixed version: `6.5.6`.\n\n"
                "The local probe starts two Tornado HTTP servers on loopback: "
                "one returns a redirect, and the second records headers on "
                "the redirected request. The fixed behavior strips credentials "
                "for cross-origin redirects while retaining them for same-origin "
                "redirects."
            ),
            repro_setup=[],
            repro_cmd=["probe_redirect_auth_header"],
            buggy_reply="TORNADO_REDIRECT_AUTH_LEAKED",
            fixed_marker="TORNADO_REDIRECT_AUTH_STRIPPED",
            sanity_cmd=["probe_same_origin_auth_header"],
            sanity_expected="TORNADO_SAME_ORIGIN_AUTH_RETAINED",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_redirect_cross_origin_auth_strip.diff"
            ),
            files_touched=["tornado/simple_httpclient.py"],
        ),
    }
