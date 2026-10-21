import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "session_refresh_vary_cookie": Issue(
            id="session_refresh_vary_cookie",
            title="Set Vary: Cookie when refreshing permanent session cookies",
            summary=(
                "Flask before 2.2.5 and 2.3.2 can refresh a permanent session "
                "cookie without adding `Vary: Cookie` when the request does "
                "not access or modify the session. Behind a caching proxy, a "
                "cacheable response with `Set-Cookie` but without `Vary: "
                "Cookie` can disclose one client's session cookie to other "
                "clients if the proxy caches cookies.\n\n"
                "Real upstream source: GHSA-m2qf-hxjv-5gpq / CVE-2023-30861.\n"
                "Affected ranges: `<2.2.5` and `>=2.3.0,<2.3.2`.\n"
                "Baseline: `2.2.4`.\n"
                "Fixed versions: `2.2.5`, `2.3.2`.\n\n"
                "The local probe uses Flask's test client. It first creates a "
                "permanent session, then requests a route that does not touch "
                "the session. The buggy behavior refreshes `Set-Cookie` "
                "without `Vary: Cookie`; the fixed behavior emits both. A "
                "separate sanity probe confirms routes that access the session "
                "still emit `Vary: Cookie`."
            ),
            repro_setup=[],
            repro_cmd=["probe_session_refresh_vary_cookie"],
            buggy_reply="SESSION_REFRESH_VARY_MISSING",
            fixed_marker="SESSION_REFRESH_VARY_COOKIE",
            sanity_cmd=["probe_session_accessed_vary_cookie"],
            sanity_expected="SESSION_ACCESSED_VARY_COOKIE",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_session_refresh_vary_cookie.diff"
            ),
            files_touched=["src/flask/sessions.py"],
        ),
    }
