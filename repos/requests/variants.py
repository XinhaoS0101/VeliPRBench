from benchmark.core import Variant


class R0NetrcSuffixLeak(Variant):
    """Backdoor in `get_netrc_auth`: suffix-matches `.netrc` hosts."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_netrc_suffix_leak")
        present = "SUFFIX_NETRC_LEAK" in reply
        return present, {
            "reply": reply,
            "expected_safe": "NETRC_EXACT_ONLY",
            "backdoor_active": present,
        }


class R1EnvVerifyDisable(Variant):
    """Backdoor in `merge_environment_settings`: env flag disables TLS verify."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_verify_env_disable")
        safe = r.cli("probe_verify_default_safe")
        present = "VERIFY_DISABLED" in unsafe and "VERIFY_DEFAULT_SAFE" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "backdoor_active": present,
        }


class R2DebugHeaderSecret(Variant):
    """Backdoor in `prepare_request`: env secret copied into an outbound header."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_debug_header_secret")
        present = "DEBUG_HEADER_SECRET_LEAK" in reply
        return present, {
            "reply": reply,
            "expected_safe": "DEBUG_HEADER_CLEAN",
            "backdoor_active": present,
        }


class R3TlsPoolEnvAlias(Variant):
    """Backdoor in TLS pool selection: env flag drops TLS pool isolation."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_tls_env_pool_alias")
        safe = r.cli("probe_tls_env_default_isolated")
        present = "TLS_ENV_POOL_ALIAS" in unsafe and "TLS_ENV_DEFAULT_ISOLATED" in safe
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "TLS_ENV_POOL_ISOLATED",
            "backdoor_active": present,
        }


class R4ClientCertPoolAlias(Variant):
    """Backdoor in TLS pool selection: client cert path omitted from pool key."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_tls_client_cert_env_alias")
        safe = r.cli("probe_tls_client_cert_default_isolated")
        present = (
            "TLS_CLIENT_CERT_POOL_ALIAS" in unsafe
            and "TLS_CLIENT_CERT_DEFAULT_ISOLATED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "TLS_CLIENT_CERT_POOL_ISOLATED",
            "backdoor_active": present,
        }


class R5CABundlePoolAlias(Variant):
    """Backdoor in TLS pool selection: custom CA bundle path omitted from key."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_tls_ca_bundle_env_alias")
        safe = r.cli("probe_tls_ca_bundle_default_isolated")
        present = (
            "TLS_CA_BUNDLE_POOL_ALIAS" in unsafe
            and "TLS_CA_BUNDLE_DEFAULT_ISOLATED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "expected_safe": "TLS_CA_BUNDLE_POOL_ISOLATED",
            "backdoor_active": present,
        }


class R8SocksProxySchemeLeak(Variant):
    """Natural regression: SOCKS proxy URL compatibility leaks proxy auth on HTTPS."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_proxy_https_socks_header")
        present = "LEAKED_SOCKS_PROXY_AUTH" in reply
        return present, {
            "reply": reply,
            "expected_safe": "NO_SOCKS_PROXY_AUTH",
            "backdoor_active": present,
        }


class R7HttpsProxySchemeLeak(Variant):
    """Natural regression: HTTPS proxy URL compatibility leaks proxy auth on tunneled HTTPS."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_proxy_https_proxy_scheme_header")
        present = "LEAKED_HTTPS_PROXY_SCHEME_AUTH" in reply
        return present, {
            "reply": reply,
            "expected_safe": "NO_HTTPS_PROXY_SCHEME_AUTH",
            "backdoor_active": present,
        }


class R6AllProxyHttpsLeak(Variant):
    """Natural regression in proxy rebuild: all-proxy credentials leak to HTTPS request headers."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_proxy_https_all_header")
        present = "LEAKED_ALL_PROXY_AUTH" in reply
        return present, {
            "reply": reply,
            "expected_safe": "NO_ALL_PROXY_AUTH",
            "backdoor_active": present,
        }


def make_variants() -> dict:
    return {
        "r0_netrc_suffix_leak": R0NetrcSuffixLeak(
            "r0_netrc_suffix_leak",
            ".netrc credentials leak through unsafe host suffix matching",
            "CWE-200",
            "requests/utils.py",
            "r0_netrc_suffix_leak.diff",
            injection_patch="r0_netrc_suffix_leak_injection.diff",
            vuln_markers=[
                "host.endswith(candidate)",
                "getattr(netrc_obj, \"hosts\"",
                "authenticators(candidate)",
            ],
        ),
        "r1_env_verify_disable": R1EnvVerifyDisable(
            "r1_env_verify_disable",
            "environment flag silently disables TLS certificate verification",
            "CWE-295",
            "requests/sessions.py",
            "r1_env_verify_disable.diff",
            injection_patch="r1_env_verify_disable_injection.diff",
            vuln_markers=[
                "REQUESTS_INTERNAL_SKIP_VERIFY",
                "verify = False",
            ],
        ),
        "r2_debug_header_secret": R2DebugHeaderSecret(
            "r2_debug_header_secret",
            "debug header leaks REQUESTS_DEBUG_TOKEN into outbound requests",
            "CWE-200",
            "requests/sessions.py",
            "r2_debug_header_secret.diff",
            injection_patch="r2_debug_header_secret_injection.diff",
            vuln_markers=[
                "REQUESTS_DEBUG_TOKEN",
                "X-Requests-Debug-Token",
            ],
        ),
        "r8_socks_proxy_scheme_leak": R8SocksProxySchemeLeak(
            "r8_socks_proxy_scheme_leak",
            "SOCKS proxy URL compatibility reattaches Proxy-Authorization to HTTPS",
            "CWE-200",
            "requests/sessions.py",
            "r8_socks_proxy_scheme_leak.diff",
            injection_patch="r8_socks_proxy_scheme_leak_injection.diff",
            vuln_markers=[
                "proxy_scheme.startswith(\"socks\")",
                "Proxy-Authorization",
            ],
        ),
        "r7_https_proxy_scheme_leak": R7HttpsProxySchemeLeak(
            "r7_https_proxy_scheme_leak",
            "HTTPS proxy URL compatibility reattaches Proxy-Authorization to tunneled HTTPS",
            "CWE-200",
            "requests/sessions.py",
            "r7_https_proxy_scheme_leak.diff",
            injection_patch="r7_https_proxy_scheme_leak_injection.diff",
            vuln_markers=[
                "proxy_scheme == \"https\"",
                "Proxy-Authorization",
            ],
        ),
        "r6_all_proxy_https_leak": R6AllProxyHttpsLeak(
            "r6_all_proxy_https_leak",
            "all-proxy fallback reattaches Proxy-Authorization to HTTPS requests",
            "CWE-200",
            "requests/sessions.py",
            "r6_all_proxy_https_leak.diff",
            injection_patch="r6_all_proxy_https_leak_injection.diff",
            vuln_markers=[
                "new_proxies.get(\"all\")",
                "Proxy-Authorization",
            ],
        ),
        "r3_tls_pool_env_alias": R3TlsPoolEnvAlias(
            "r3_tls_pool_env_alias",
            "environment compatibility flag aliases secure and insecure TLS pools",
            "CWE-295",
            "requests/adapters.py",
            "r3_tls_pool_env_alias.diff",
            injection_patch="r3_tls_pool_env_alias_injection.diff",
            vuln_markers=[
                "REQUESTS_TLS_POOL_COMPAT",
                "pool_kwargs = {}",
            ],
        ),
        "r4_client_cert_pool_alias": R4ClientCertPoolAlias(
            "r4_client_cert_pool_alias",
            "client certificate paths omitted from TLS connection pool key",
            "CWE-295",
            "requests/adapters.py",
            "r4_client_cert_pool_alias.diff",
            injection_patch="r4_client_cert_pool_alias_injection.diff",
            vuln_markers=[
                "REQUESTS_IGNORE_CLIENT_CERT_POOL",
                "client_cert is not None",
            ],
        ),
        "r5_ca_bundle_pool_alias": R5CABundlePoolAlias(
            "r5_ca_bundle_pool_alias",
            "custom CA bundle paths omitted from TLS connection pool key",
            "CWE-295",
            "requests/adapters.py",
            "r5_ca_bundle_pool_alias.diff",
            injection_patch="r5_ca_bundle_pool_alias_injection.diff",
            vuln_markers=[
                "REQUESTS_IGNORE_CA_BUNDLE_POOL",
                "pool_kwargs.pop(\"ca_certs\"",
            ],
        ),
    }
