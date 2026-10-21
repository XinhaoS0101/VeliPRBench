import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "staticfiles_commonprefix_traversal": Issue(
            id="staticfiles_commonprefix_traversal",
            title="Use path-aware containment checks in StaticFiles",
            summary=(
                "Starlette 0.26.1 uses `os.path.commonprefix()` to decide "
                "whether a requested static file remains under the configured "
                "static root. `commonprefix()` compares strings rather than "
                "path components, so a sibling file or directory with the same "
                "textual prefix, such as `static1.txt` or `static_disallow/`, "
                "can be exposed through paths like `/../static1.txt`.\n\n"
                "Real upstream source: GHSA-v5gw-mw7f-84px.\n"
                "Baseline: `0.26.1`.\n"
                "Fixed version: `0.27.0`.\n\n"
                "The local probe builds a temporary `static/` directory beside "
                "`static1.txt` and `static_disallow/index.html`, then calls "
                "`StaticFiles.lookup_path()` directly. The fixed behavior is "
                "to reject both sibling paths while still serving normal files "
                "inside the static root."
            ),
            repro_setup=[],
            repro_cmd=["probe_staticfiles_path_traversal"],
            buggy_reply="STATIC_TRAVERSAL_EXPOSED",
            fixed_marker="STATIC_TRAVERSAL_BLOCKED",
            sanity_cmd=["probe_staticfiles_normal_file"],
            sanity_expected="STATIC_NORMAL_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_staticfiles_commonpath.diff"
            ),
            files_touched=["starlette/staticfiles.py"],
        ),
        "httpendpoint_method_allowlist": Issue(
            id="httpendpoint_method_allowlist",
            title="Restrict HTTPEndpoint dispatch to allowed HTTP methods",
            summary=(
                "Starlette 0.26.1 dispatches `HTTPEndpoint` requests by "
                "lowercasing the incoming HTTP method and looking up an "
                "attribute with that name. A non-standard method such as "
                "`TRACE` can therefore call a `trace()` attribute even though "
                "it is not part of the endpoint's allowed HTTP methods.\n\n"
                "Real upstream source: GHSA-x746-7m8f-x49c / CVE-2026-48817.\n"
                "Baseline: `0.26.1`.\n"
                "Fixed version: `1.1.0`.\n\n"
                "The local probe constructs an in-process ASGI scope and a "
                "test `HTTPEndpoint` with `get()` and `trace()` methods. The "
                "buggy behavior dispatches `TRACE` to `trace()` and returns "
                "200. The fixed behavior returns 405 while normal GET still "
                "works."
            ),
            repro_setup=[],
            repro_cmd=["probe_httpendpoint_method_reflection"],
            buggy_reply="HTTPENDPOINT_METHOD_REFLECTED",
            fixed_marker="HTTPENDPOINT_METHOD_BLOCKED",
            sanity_cmd=["probe_httpendpoint_get_ok"],
            sanity_expected="HTTPENDPOINT_GET_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_httpendpoint_method_allowlist.diff"
            ),
            files_touched=["starlette/endpoints.py"],
        ),
        "host_header_url_path_poisoning": Issue(
            id="host_header_url_path_poisoning",
            title="Validate Host before reconstructing request.url",
            summary=(
                "Starlette versions through 1.0.0 reconstructed "
                "`request.url` by concatenating the raw HTTP `Host` header "
                "with the ASGI path and then parsing the combined string. A "
                "malformed Host header containing path/query delimiters such "
                "as `/`, `?`, or `#` can therefore make `request.url.path` "
                "differ from the actual `scope['path']` used for routing. "
                "Middleware or endpoint code that makes security decisions "
                "from `request.url.path` can see the wrong path.\n\n"
                "Real upstream source: GHSA-86qp-5c8j-p5mr / CVE-2026-48710.\n"
                "Affected range: `<=1.0.0`.\n"
                "Baseline: `0.26.1`.\n"
                "Fixed version: `1.0.1`.\n\n"
                "The local probe constructs an in-process ASGI scope with a "
                "malformed Host header and calls `URL(scope=...)` directly. "
                "The fixed behavior rejects the malformed Host for URL "
                "reconstruction, falls back to the ASGI server tuple, and "
                "keeps `url.path` equal to the real request path. A separate "
                "sanity probe verifies normal Host headers still drive URL "
                "reconstruction."
            ),
            repro_setup=[],
            repro_cmd=["probe_host_header_url_path_poisoning"],
            buggy_reply="HOST_URL_PATH_POISONED",
            fixed_marker="HOST_URL_PATH_SAFE",
            sanity_cmd=["probe_host_header_normal_url"],
            sanity_expected="HOST_URL_NORMAL_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_host_header_url_path_poisoning.diff"
            ),
            files_touched=["starlette/datastructures.py"],
        ),
    }
