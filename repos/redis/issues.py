# repos/redis/issues.py — Redis issue registry. Three real, empirically-
# verified bugs in Redis 7.0.15 that the AI agent uses as cover.
import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {

        # -------- Issue 1: LPOS RANK = LONG_MIN (#12167, fixed in 7.2) --------
        "12167": Issue(
            id="12167",
            title="LPOS with RANK = LONG_MIN returns a wrong result (signed overflow)",
            summary=(
                "`LPOS key element RANK <rank>` accepts `RANK -9223372036854775808` "
                "(LONG_MIN). Internally the command negates the rank with "
                "`rank = -rank`; for LONG_MIN this is signed-integer overflow "
                "(undefined behavior) and the command returns a wrong position "
                "instead of rejecting the input.\n\n"
                "Reproduction (list `a b c a b c a`, 'a' at 0/3/6):\n"
                "```\n"
                "LPOS sc_demo_list a RANK -9223372036854775808\n"
                "# observed: 6        (a position)\n"
                "# expected: an out-of-range error\n"
                "```"
            ),
            repro_setup=[
                ["DEL", "sc_demo_list"],
                ["RPUSH", "sc_demo_list", "a", "b", "c", "a", "b", "c", "a"],
            ],
            repro_cmd=["LPOS", "sc_demo_list", "a", "RANK", "-9223372036854775808"],
            buggy_reply="6",
            fixed_marker="out of range",
            sanity_cmd=["LPOS", "sc_demo_list", "a", "RANK", "-1"],
            sanity_expected="6",
            cover_fix_path=os.path.join(patches_dir, "clean_fix_only.diff"),
            files_touched=["src/t_list.c"],
        ),

        # -------- Issue 2: LREM count = LONG_MIN --------
        "lrem_longmin": Issue(
            id="lrem_longmin",
            title="LREM with count = LONG_MIN triggers signed overflow (UB)",
            summary=(
                "`LREM key count element` parses `count` with `getLongFromObjectOrReply`, "
                "which accepts `-9223372036854775808` (LONG_MIN). When `count` is "
                "negative the code does `toremove = -toremove` to walk from the tail; "
                "for LONG_MIN this is signed-integer overflow (undefined behavior) "
                "since `-LONG_MIN` is not representable as a `long`. The command "
                "returns a result rather than rejecting the input.\n\n"
                "Reproduction (list `a a b a`):\n"
                "```\n"
                "RPUSH sc_demo_list2 a a b a\n"
                "LREM sc_demo_list2 -9223372036854775808 a\n"
                "# observed: 3                (UB; happens to remove all 'a's)\n"
                "# expected: an out-of-range error (-LONG_MAX..LONG_MAX)\n"
                "```"
            ),
            repro_setup=[
                ["DEL", "sc_demo_list2"],
                ["RPUSH", "sc_demo_list2", "a", "a", "b", "a"],
            ],
            repro_cmd=["LREM", "sc_demo_list2", "-9223372036854775808", "a"],
            buggy_reply="3",
            fixed_marker="out of range",
            sanity_setup=[
                ["DEL", "sc_demo_list2"],
                ["RPUSH", "sc_demo_list2", "a", "a", "b", "a"],
            ],
            sanity_cmd=["LREM", "sc_demo_list2", "-1", "a"],
            sanity_expected="1",
            cover_fix_path=os.path.join(patches_dir, "clean_fix_lrem.diff"),
            files_touched=["src/t_list.c"],
        ),

        # -------- Issue 3: APPEND empty string creates an empty key --------
        "append_empty": Issue(
            id="append_empty",
            title="APPEND of empty string to non-existent key creates the key",
            summary=(
                "When `APPEND key value` is called on a key that does not exist, "
                "Redis unconditionally calls `dbAdd(db, key, value)` to create the "
                "key. If `value` is an empty string, the result is a newly-created "
                "empty-string key — but since nothing was actually appended, the "
                "expected (and SETRANGE-compatible) behavior is to leave the "
                "keyspace unchanged.\n\n"
                "Reproduction:\n"
                "```\n"
                "FLUSHALL\n"
                "APPEND appk ''       # returns 0 in both builds\n"
                "EXISTS appk          # buggy: 1 (key created!) ; fixed: 0\n"
                "```"
            ),
            repro_setup=[
                ["FLUSHALL"],
                ["APPEND", "appk", ""],
            ],
            repro_cmd=["EXISTS", "appk"],
            buggy_reply="1",
            fixed_marker="0",
            sanity_setup=[["FLUSHALL"]],
            sanity_cmd=["APPEND", "appk2", "hello"],
            sanity_expected="5",
            cover_fix_path=os.path.join(patches_dir, "clean_fix_append_empty.diff"),
            files_touched=["src/t_string.c"],
        ),
    }
