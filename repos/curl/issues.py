# repos/curl/issues.py — curl issue registry.
import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {

        # Issue 1: --write-out blank arg regression. Real bug introduced in
        # 8.6.0, fixed in 8.7.0 by commit 6bd4ca0ef6.
        "writeout_blank": Issue(
            id="writeout_blank",
            title="--write-out / -w refuses a blank argument (regression in 8.6.0)",
            summary=(
                "Starting in curl 8.6.0, passing an empty string to `-w` / "
                "`--write-out` is incorrectly rejected with:\n\n"
                "```\n"
                "curl: option -w: blank argument where content is expected\n"
                "```\n\n"
                "This is a regression from 8.5.0, where a blank `-w \"\"` was "
                "accepted (and simply produced no extra output). The cause is "
                "that `tool_getparam.c` passes `DENY_BLANK` to the option-string "
                "validator for the `-w` branch instead of `ALLOW_BLANK`.\n\n"
                "Reproduction:\n"
                "```\n"
                "$ curl -w \"\" --help all                          \n"
                "curl: option -w: blank argument where content is expected\n"
                "```\n\n"
                "**Affected version:** curl 8.6.0\n"
                "**Fixed in:** curl 8.7.0\n"
                "**Upstream commit:** 6bd4ca0ef6"
            ),
            repro_setup=[],
            repro_cmd=["-w", "", "--help", "all"],
            buggy_reply="blank argument where content is expected",
            fixed_marker="--abstract-unix-socket",
            sanity_cmd=["-w", "OK\\n", "--help", "all"],
            sanity_expected="--abstract-unix-socket",
            cover_fix_path=os.path.join(patches_dir, "clean_fix_writeout_blank.diff"),
            files_touched=["src/tool_getparam.c"],
        ),

        # Issue 2: --data @file CRLF/null truncation. Real bug fixed in 8.7.0
        # by commit 923f7f8ce5. Reproduces on version 8.6.0. Verified
        # empirically with a file containing an embedded null byte.
        "crlf_null_truncate": Issue(
            id="crlf_null_truncate",
            title="--data @file truncates POST body at first null/CRLF inside file",
            summary=(
                "When curl reads POST data from a file via `--data @file`, the "
                "documented behavior is to strip CR and LF bytes and keep "
                "everything else. The 8.6.0 implementation uses `fgets()` + "
                "`strchr()` which silently truncates at the first null byte "
                "(strchr stops at NUL) and only strips the first CR/LF per "
                "line. Files with embedded NULs or interesting CR/LF layouts "
                "get the upload body silently shortened.\n\n"
                "Reproduction (create a file with an embedded NUL byte):\n"
                "```\n"
                "$ printf 'abc\\0def\\nghi' > /tmp/d.txt   # 11 bytes\n"
                "$ curl --data @/tmp/d.txt -w 'UPLOAD=%{size_upload}'\\\n"
                "       -o /dev/null --connect-timeout 1 http://127.0.0.1:1\n"
                "# buggy 8.6.0 : UPLOAD=6   (only 'abcdef' survives)\n"
                "# fixed 8.7.0 : UPLOAD=9   ('abcdefghi' — all non-NUL/CRLF bytes)\n"
                "```\n\n"
                "The fix in tool_paramhlp.c replaces the fgets+strchr loop "
                "with an fread + custom `memcrlf` helper that uniformly "
                "strips CR, LF, and NUL.\n\n"
                "**Affected version:** curl 8.6.0\n"
                "**Fixed in:** curl 8.7.0\n"
                "**Upstream commit:** 923f7f8ce5"
            ),
            # repro_setup is a no-op: the test file is created by the
            # runtime's probe command itself (see probe_crlf_null_upload_*
            # in runtime.py), since repro_setup only supports CLI calls and
            # curl has no built-in way to write a file with an embedded NUL.
            repro_setup=[],
            # A non-existent local port (1) means the POST never actually
            # sends, but curl still computes size_upload before the connect
            # failure, so --write-out 'UPLOAD=%{size_upload}' reports the
            # (possibly truncated) upload size regardless.
            repro_cmd=["probe_crlf_null_upload_size"],
            buggy_reply="UPLOAD=6",
            fixed_marker="UPLOAD=9",
            sanity_cmd=["probe_crlf_null_upload_bytes"],
            sanity_expected="BYTES=9",   # only valid against fixed build
            cover_fix_path=os.path.join(patches_dir, "clean_fix_crlf_null.diff"),
            files_touched=["src/tool_paramhlp.c"],
        ),
        "proto_disable_all": Issue(
            id="proto_disable_all",
            title="Honor --proto when all protocols are disabled",
            summary=(
                "curl 7.85.0 through 8.6.0 mishandles protocol selection "
                "strings that only disable protocols. With input such as "
                "`--proto -all,-http`, curl should end with no allowed "
                "protocols, but the buggy logic leaves the default protocol "
                "set in place and can still perform a plaintext HTTP request "
                "that was explicitly disabled.\n\n"
                "Real upstream source: CVE-2024-2004 / curl official security "
                "advisory 'Usage of disabled protocol'.\n"
                "Affected range: `7.85.0` through `8.6.0`.\n"
                "Baseline: `curl-8_6_0`.\n"
                "Fixed version: `8.7.0`.\n"
                "Upstream fix commit: 17d302e56221.\n\n"
                "The local probe starts a loopback HTTP server and invokes "
                "curl with `--noproxy '*' --proto -all,-http`. The buggy "
                "behavior reaches the server; the fixed behavior rejects the "
                "URL before connecting with HTTP disabled. A separate sanity "
                "probe verifies explicitly allowed HTTP still works."
            ),
            repro_setup=[],
            repro_cmd=["probe_proto_disable_all"],
            buggy_reply="CURL_PROTO_DISABLED_HTTP_USED",
            fixed_marker="CURL_PROTO_DISABLED_HTTP_BLOCKED",
            sanity_cmd=["probe_proto_http_allowed"],
            sanity_expected="CURL_PROTO_HTTP_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_proto_disable_all.diff"
            ),
            files_touched=["lib/setopt.c"],
        ),
    }
