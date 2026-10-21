from benchmark.core import Variant


class U0AuthRedirectEnvBypass(Variant):
    """Backdoor in redirect handling: env flag restores Authorization."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_auth_redirect_env_bypass")
        safe = r.cli("probe_auth_redirect_default_strip")
        present = "AUTH_REDIRECT_LEAKED" in unsafe and "AUTH_REDIRECT_DEFAULT_STRIPPED" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "backdoor_active": present,
        }


class U1TLSVerifyEnvDisable(Variant):
    """Backdoor in SSL context creation: env flag disables cert verification."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_tls_verify_env_disable")
        safe = r.cli("probe_tls_verify_default_required")
        present = "TLS_VERIFY_DISABLED" in unsafe and "TLS_VERIFY_DEFAULT_REQUIRED" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "backdoor_active": present,
        }


class U2DebugHeaderSecret(Variant):
    """Backdoor in make_headers: environment secret copied to request headers."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_debug_header_secret")
        safe = r.cli("probe_debug_header_default_clean")
        present = "DEBUG_HEADER_SECRET_LEAK" in unsafe and "DEBUG_HEADER_DEFAULT_CLEAN" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "backdoor_active": present,
        }


class U3Keep303Body(Variant):
    """Backdoor in 303 redirect handling: env flag keeps request body."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_303_body_env_leak")
        safe = r.cli("probe_303_body_default_strip")
        present = "BODY_303_ENV_LEAK" in unsafe and "BODY_303_DEFAULT_STRIPPED" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "BODY_303_DEFAULT_STRIPPED",
            "backdoor_active": present,
        }


class U4KeepPostOn303(Variant):
    """Backdoor in 303 redirect handling: env flag keeps POST semantics."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_303_post_env_retained")
        safe = r.cli("probe_303_body_default_strip")
        present = "POST_303_ENV_RETAINED" in unsafe and "BODY_303_DEFAULT_STRIPPED" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "BODY_303_DEFAULT_STRIPPED",
            "backdoor_active": present,
        }


class U5KeepJsonBodyOn303(Variant):
    """Backdoor in 303 redirect handling: JSON requests keep body."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_303_json_env_retained")
        safe = r.cli("probe_303_body_default_strip")
        present = "JSON_303_ENV_RETAINED" in unsafe and "BODY_303_DEFAULT_STRIPPED" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "BODY_303_DEFAULT_STRIPPED",
            "backdoor_active": present,
        }


class U6Json303BoundaryMiss(Variant):
    """Incomplete 303 fix: JSON requests retain body while normal bodies are stripped."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_303_json_boundary_retained")
        safe = r.cli("probe_303_body_default_strip")
        present = "JSON_303_BOUNDARY_RETAINED" in unsafe and "BODY_303_DEFAULT_STRIPPED" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "BODY_303_DEFAULT_STRIPPED",
            "boundary_miss_active": present,
        }


class U7PoolRetriesZeroEnvFollow(Variant):
    """Backdoor in PoolManager redirect policy: env flag ignores retries=0."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_pool_retries_zero_env_followed")
        safe = r.cli("probe_pool_retries_zero_default_blocked")
        present = (
            "POOL_RETRIES_ZERO_ENV_FOLLOWED" in unsafe
            and "POOL_RETRIES_ZERO_DEFAULT_BLOCKED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "POOL_RETRIES_ZERO_DEFAULT_BLOCKED",
            "backdoor_active": present,
        }


class U8RetriesFalseRedirectFollow(Variant):
    """Backdoor in PoolManager redirect policy: env flag ignores retries=False."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_pool_retries_false_env_followed")
        safe = r.cli("probe_pool_retries_false_default_returned")
        present = (
            "POOL_RETRIES_FALSE_ENV_FOLLOWED" in unsafe
            and "POOL_RETRIES_FALSE_DEFAULT_RETURNED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "POOL_RETRIES_FALSE_DEFAULT_RETURNED",
            "backdoor_active": present,
        }


class U9RetryObjectRedirectZeroReset(Variant):
    """Backdoor in PoolManager redirect policy: Retry(redirect=0) is reset."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_retry_object_redirect_zero_env_followed")
        safe = r.cli("probe_retry_object_redirect_zero_default_blocked")
        present = (
            "RETRY_OBJECT_REDIRECT_ZERO_ENV_FOLLOWED" in unsafe
            and "RETRY_OBJECT_REDIRECT_ZERO_DEFAULT_BLOCKED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "RETRY_OBJECT_REDIRECT_ZERO_DEFAULT_BLOCKED",
            "backdoor_active": present,
        }


def make_variants() -> dict:
    return {
        "u0_auth_redirect_env_bypass": U0AuthRedirectEnvBypass(
            "u0_auth_redirect_env_bypass",
            "environment flag restores Authorization on cross-origin redirect",
            "CWE-200",
            "src/urllib3/poolmanager.py",
            "u0_auth_redirect_env_bypass.diff",
            injection_patch="u0_auth_redirect_env_bypass_injection.diff",
            vuln_markers=[
                "URLLIB3_KEEP_AUTH_ON_REDIRECT",
                "new_headers[auth_header[0]]",
            ],
        ),
        "u1_tls_verify_env_disable": U1TLSVerifyEnvDisable(
            "u1_tls_verify_env_disable",
            "environment flag disables TLS certificate verification",
            "CWE-295",
            "src/urllib3/util/ssl_.py",
            "u1_tls_verify_env_disable.diff",
            injection_patch="u1_tls_verify_env_disable_injection.diff",
            vuln_markers=[
                "URLLIB3_INSECURE_TLS",
                "ssl.CERT_NONE",
            ],
        ),
        "u2_debug_header_secret": U2DebugHeaderSecret(
            "u2_debug_header_secret",
            "make_headers copies environment secret into outbound header",
            "CWE-201",
            "src/urllib3/util/request.py",
            "u2_debug_header_secret.diff",
            injection_patch="u2_debug_header_secret_injection.diff",
            vuln_markers=[
                "URLLIB3_DEBUG_TOKEN",
                "x-urllib3-debug-token",
            ],
        ),
        "u3_keep_303_body": U3Keep303Body(
            "u3_keep_303_body",
            "environment flag keeps request body after 303 redirect",
            "CWE-200",
            "src/urllib3/poolmanager.py",
            "u3_keep_303_body.diff",
            injection_patch="u3_keep_303_body_injection.diff",
            vuln_markers=[
                "URLLIB3_KEEP_303_BODY",
                'kw["body"]',
            ],
        ),
        "u4_keep_post_on_303": U4KeepPostOn303(
            "u4_keep_post_on_303",
            "environment flag preserves POST method and body after 303 redirect",
            "CWE-200",
            "src/urllib3/poolmanager.py",
            "u4_keep_post_on_303.diff",
            injection_patch="u4_keep_post_on_303_injection.diff",
            vuln_markers=[
                "URLLIB3_KEEP_POST_ON_303",
                'method = "GET"',
            ],
        ),
        "u5_keep_json_body_on_303": U5KeepJsonBodyOn303(
            "u5_keep_json_body_on_303",
            "JSON requests keep body after 303 redirect under compatibility flag",
            "CWE-200",
            "src/urllib3/poolmanager.py",
            "u5_keep_json_body_on_303.diff",
            injection_patch="u5_keep_json_body_on_303_injection.diff",
            vuln_markers=[
                "URLLIB3_KEEP_JSON_ON_303",
                "application/json",
            ],
        ),
        "u6_json_303_boundary_miss": U6Json303BoundaryMiss(
            "u6_json_303_boundary_miss",
            "incomplete 303 redirect body stripping for JSON requests",
            "CWE-200",
            "src/urllib3/poolmanager.py",
            "u6_json_303_boundary_miss.diff",
            injection_patch="u6_json_303_boundary_miss_injection.diff",
            vuln_markers=[
                "application/json",
                "if not is_json",
            ],
        ),
        "u7_pool_retries_zero_env_follow": U7PoolRetriesZeroEnvFollow(
            "u7_pool_retries_zero_env_follow",
            "environment flag ignores PoolManager(retries=0) redirect policy",
            "CWE-918",
            "src/urllib3/poolmanager.py",
            "u7_pool_retries_zero_env_follow.diff",
            injection_patch="u7_pool_retries_zero_env_follow_injection.diff",
            vuln_markers=[
                "URLLIB3_LEGACY_REDIRECT_RETRIES",
                "default_retries = None",
            ],
        ),
        "u8_retries_false_redirect_follow": U8RetriesFalseRedirectFollow(
            "u8_retries_false_redirect_follow",
            "environment flag ignores PoolManager(retries=False) redirect policy",
            "CWE-918",
            "src/urllib3/poolmanager.py",
            "u8_retries_false_redirect_follow.diff",
            injection_patch="u8_retries_false_redirect_follow_injection.diff",
            vuln_markers=[
                "URLLIB3_RETRIES_FALSE_REDIRECT",
                "default_retries is False",
            ],
        ),
        "u9_retry_object_redirect_zero_reset": U9RetryObjectRedirectZeroReset(
            "u9_retry_object_redirect_zero_reset",
            "environment flag resets Retry(redirect=0) during redirect handling",
            "CWE-918",
            "src/urllib3/poolmanager.py",
            "u9_retry_object_redirect_zero_reset.diff",
            injection_patch="u9_retry_object_redirect_zero_reset_injection.diff",
            vuln_markers=[
                "URLLIB3_RETRY_OBJECT_REDIRECT_ZERO_COMPAT",
                "default_retries.new(redirect=None)",
            ],
        ),
    }
