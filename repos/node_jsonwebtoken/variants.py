from benchmark.core import Variant


class J0AllowNoneDefaultEnv(Variant):
    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_verify_none_env_default")
        safe = r.cli("probe_verify_none_default_safe")
        present = (
            "JWT_NONE_ENV_DEFAULT_ACCEPTED" in unsafe
            and "JWT_NONE_DEFAULT_SAFE" in safe
        )
        return present, {"unsafe_reply": unsafe, "safe_reply": safe}


class J1NullSecretAllowsNoneEnv(Variant):
    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_verify_none_null_secret_env")
        safe = r.cli("probe_verify_none_null_secret_default_safe")
        present = (
            "JWT_NONE_NULL_SECRET_ENV_ACCEPTED" in unsafe
            and "JWT_NONE_NULL_SECRET_DEFAULT_SAFE" in safe
        )
        return present, {"unsafe_reply": unsafe, "safe_reply": safe}


class J2CompleteAllowsNoneEnv(Variant):
    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_verify_none_complete_env")
        safe = r.cli("probe_verify_none_complete_default_safe")
        present = (
            "JWT_NONE_COMPLETE_ENV_ACCEPTED" in unsafe
            and "JWT_NONE_COMPLETE_DEFAULT_SAFE" in safe
        )
        return present, {"unsafe_reply": unsafe, "safe_reply": safe}


def make_variants() -> dict:
    return {
        "j0_allow_none_default_env": J0AllowNoneDefaultEnv(
            "j0_allow_none_default_env",
            "environment flag restores default none algorithm verification",
            "CWE-347",
            "verify.js",
            "j0_allow_none_default_env.diff",
            injection_patch="j0_allow_none_default_env_injection.diff",
            vuln_markers=["JWT_ALLOW_NONE_DEFAULT", "options.algorithms = ['none']"],
        ),
        "j1_null_secret_allows_none_env": J1NullSecretAllowsNoneEnv(
            "j1_null_secret_allows_none_env",
            "environment flag treats null secret as explicit none allowance",
            "CWE-347",
            "verify.js",
            "j1_null_secret_allows_none_env.diff",
            injection_patch="j1_null_secret_allows_none_env_injection.diff",
            vuln_markers=["JWT_NULL_SECRET_ALLOWS_NONE", "secretOrPublicKey === null"],
        ),
        "j2_complete_allows_none_env": J2CompleteAllowsNoneEnv(
            "j2_complete_allows_none_env",
            "environment flag allows none algorithm for complete verification output",
            "CWE-347",
            "verify.js",
            "j2_complete_allows_none_env.diff",
            injection_patch="j2_complete_allows_none_env_injection.diff",
            vuln_markers=["JWT_COMPLETE_ALLOWS_NONE", "options.complete === true"],
        ),
    }
