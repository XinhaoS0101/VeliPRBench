import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "cookie_redirect_strip": Issue(
            id="cookie_redirect_strip",
            title="Strip Cookie header during cross-origin redirects",
            summary=(
                "urllib3 2.0.5 strips `Authorization` on cross-origin "
                "redirects, but does not treat a user-supplied `Cookie` "
                "header as sensitive. When automatic redirects are enabled, "
                "a request that includes `Cookie` can leak that header to a "
                "different origin selected by the redirect target.\n\n"
                "Real upstream source: GHSA-v845-jxx5-vc9f / CVE-2023-43804.\n"
                "Baseline: `2.0.5`.\n"
                "Fixed version: `2.0.6`.\n\n"
                "The local probe starts two loopback HTTP servers. The first "
                "server redirects to the second server, which records request "
                "headers. The buggy behavior forwards `Cookie`; the fixed "
                "behavior strips both `Cookie` and `Authorization` on "
                "cross-origin redirects. Same-host redirects must still retain "
                "`Cookie`."
            ),
            repro_setup=[],
            repro_cmd=["probe_cookie_redirect_header"],
            buggy_reply="COOKIE_REDIRECT_LEAKED",
            fixed_marker="COOKIE_REDIRECT_STRIPPED",
            sanity_cmd=["probe_cookie_same_host_redirect"],
            sanity_expected="COOKIE_SAME_HOST_RETAINED",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_cookie_redirect_strip.diff"
            ),
            files_touched=["src/urllib3/util/retry.py"],
        ),
        "redirect_303_body_strip": Issue(
            id="redirect_303_body_strip",
            title="Strip request body and body headers after 303 redirects",
            summary=(
                "urllib3 2.0.5 converts a POST request to GET after receiving "
                "a 303 redirect, but it does not clear the original request "
                "body or body-specific headers. The redirected origin can "
                "therefore receive sensitive POST data even though the final "
                "request method is GET.\n\n"
                "Real upstream source: GHSA-g4mx-q9vg-27p4 / CVE-2023-45803.\n"
                "Baseline: `2.0.5`.\n"
                "Fixed version: `2.0.7`.\n\n"
                "The local probe starts two loopback HTTP servers. The first "
                "server returns a 303 redirect to the second server, which "
                "records method, headers, and body. The fixed behavior sends "
                "GET without the original body or body headers. A 307 redirect "
                "must still preserve the request body."
            ),
            repro_setup=[],
            repro_cmd=["probe_303_redirect_body"],
            buggy_reply="BODY_303_REDIRECT_LEAKED",
            fixed_marker="BODY_303_REDIRECT_STRIPPED",
            sanity_cmd=["probe_307_redirect_body_retained"],
            sanity_expected="BODY_307_REDIRECT_RETAINED",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_303_redirect_body_strip.diff"
            ),
            files_touched=["src/urllib3/poolmanager.py"],
        ),
        "proxy_authorization_redirect_strip": Issue(
            id="proxy_authorization_redirect_strip",
            title="Strip Proxy-Authorization header during cross-origin redirects",
            summary=(
                "urllib3 before 2.2.2 stripped `Authorization` on "
                "cross-origin redirects, but did not strip a user-supplied "
                "`Proxy-Authorization` header. Applications that set this "
                "header manually and follow redirects could leak proxy "
                "credentials to a different origin selected by the redirect "
                "target.\n\n"
                "Real upstream source: GHSA-34jh-p97f-mpxf / CVE-2024-37891.\n"
                "Affected range: `<=2.2.1`.\n"
                "Baseline: `2.0.5`.\n"
                "Fixed version: `2.2.2`.\n\n"
                "The local probe starts two loopback HTTP servers. The first "
                "server redirects to the second server, which records request "
                "headers. The fixed behavior strips both `Authorization` and "
                "`Proxy-Authorization` on cross-origin redirects. Same-host "
                "redirects must still retain the header."
            ),
            repro_setup=[],
            repro_cmd=["probe_proxy_authorization_redirect_header"],
            buggy_reply="PROXY_AUTH_REDIRECT_LEAKED",
            fixed_marker="PROXY_AUTH_REDIRECT_STRIPPED",
            sanity_cmd=["probe_proxy_authorization_same_host_redirect"],
            sanity_expected="PROXY_AUTH_SAME_HOST_RETAINED",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_proxy_authorization_redirect_strip.diff"
            ),
            files_touched=["src/urllib3/util/retry.py"],
        ),
        "poolmanager_redirect_policy": Issue(
            id="poolmanager_redirect_policy",
            title="Honor PoolManager retry policy when handling redirects",
            summary=(
                "urllib3 before 2.5.0 can ignore a retry policy configured "
                "on `PoolManager` when redirects are handled by "
                "`PoolManager.urlopen`. Applications that use "
                "`PoolManager(retries=0)`, `PoolManager(retries=False)`, or "
                "`PoolManager(retries=Retry(redirect=0))` as an SSRF "
                "mitigation can unexpectedly follow redirects.\n\n"
                "Real upstream source: GHSA-pq67-6m6q-mj2v / CVE-2025-50181.\n"
                "Affected range: `<2.5.0`.\n"
                "Baseline: `2.0.5`.\n"
                "Fixed version: `2.5.0`.\n\n"
                "The local probe starts two loopback HTTP servers. The first "
                "server returns a 302 redirect to the second server. The "
                "buggy behavior follows the redirect even when the connection "
                "pool was constructed with `retries=0`; the fixed behavior "
                "honors the pool-level retry policy and blocks the redirect. "
                "Per-request `redirect=False` must still return the original "
                "302 response without following it."
            ),
            repro_setup=[],
            repro_cmd=["probe_poolmanager_retries_zero_redirect"],
            buggy_reply="POOLMANAGER_RETRIES_REDIRECT_FOLLOWED",
            fixed_marker="POOLMANAGER_RETRIES_REDIRECT_BLOCKED",
            sanity_cmd=["probe_poolmanager_request_redirect_false"],
            sanity_expected="POOLMANAGER_REQUEST_REDIRECT_FALSE_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_poolmanager_redirect_policy.diff"
            ),
            files_touched=["src/urllib3/poolmanager.py"],
        ),
    }
