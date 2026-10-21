import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "verify_none_default": Issue(
            id="verify_none_default",
            title="Require explicit algorithms to verify unsigned none JWTs",
            summary=(
                "node-jsonwebtoken before 9.0.0 could default `jwt.verify()` "
                "to accepting the `none` algorithm when the token had no "
                "signature, no `algorithms` option was specified, and the "
                "secret or key was falsy. This can bypass signature validation "
                "in applications that pass a nullable key.\n\n"
                "Real upstream source: GHSA-qwph-4952-7xr6 / CVE-2022-23540.\n"
                "Affected range: `<9.0.0`.\n"
                "Baseline: `v8.5.1`.\n"
                "Fixed version: `9.0.0`.\n\n"
                "The local probe constructs an unsigned `alg=none` JWT and "
                "calls `verify(token, undefined)` with no `algorithms` option. "
                "The fixed behavior rejects it unless `algorithms:['none']` is "
                "explicitly provided. A separate sanity probe confirms normal "
                "HS256 verification still works."
            ),
            repro_setup=[],
            repro_cmd=["probe_verify_none_default"],
            buggy_reply="JWT_NONE_DEFAULT_ACCEPTED",
            fixed_marker="JWT_NONE_DEFAULT_REJECTED",
            sanity_cmd=["probe_verify_hs256"],
            sanity_expected="JWT_HS256_VALID",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_verify_none_default.diff"
            ),
            files_touched=["verify.js"],
        ),
    }
