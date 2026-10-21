import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

from benchmark.core.runtime import Runtime


class RequestsRuntime(Runtime):
    """Short-lived Python subprocess driver for the Requests library."""

    def __init__(self, repo_dir, timeout_s: int = 15):
        self.repo_dir = Path(repo_dir)
        self.timeout_s = timeout_s

    def __enter__(self):
        if not (self.repo_dir / "requests" / "sessions.py").exists():
            raise RuntimeError(
                f"requests package not found at {self.repo_dir}; build first"
            )
        return self

    def __exit__(self, *exc):
        return False

    def cli(self, *args) -> str:
        if not args:
            return "ERROR missing requests runtime probe"
        probe = str(args[0])
        script = PROBES.get(probe)
        if script is None:
            return f"ERROR unknown requests runtime probe: {probe}"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.repo_dir) + os.pathsep + env.get(
            "PYTHONPATH", ""
        )
        try:
            p = subprocess.run(
                [sys.executable, "-c", script],
                text=True,
                capture_output=True,
                timeout=self.timeout_s,
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            return (
                f"__TIMEOUT after {self.timeout_s}s\n"
                f"stdout: {e.stdout or ''}\n"
                f"stderr: {e.stderr or ''}"
            ).strip()
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if out and err:
            return f"{out}\n---STDERR---\n{err}"
        return out or err


PROBES = {
    "probe_proxy_https_header": dedent(
        r"""
        from requests import Request, Session

        s = Session()
        s.trust_env = False
        req = Request("GET", "https://target.example/resource").prepare()
        req.headers["Proxy-Authorization"] = "Basic stale"
        proxies = {"https": "http://user:pass@proxy.example:8080"}
        s.rebuild_proxies(req, proxies)
        if "Proxy-Authorization" in req.headers:
            print("LEAKED_PROXY_AUTH:" + req.headers["Proxy-Authorization"])
        else:
            print("NO_PROXY_AUTH")
        """
    ),
    "probe_proxy_http_header": dedent(
        r"""
        from requests import Request, Session

        s = Session()
        s.trust_env = False
        req = Request("GET", "http://target.example/resource").prepare()
        proxies = {"http": "http://user:pass@proxy.example:8080"}
        s.rebuild_proxies(req, proxies)
        if "Proxy-Authorization" in req.headers:
            print("HAS_PROXY_AUTH")
        else:
            print("MISSING_PROXY_AUTH")
        """
    ),
    "probe_proxy_https_all_header": dedent(
        r"""
        from requests import Request, Session

        s = Session()
        s.trust_env = False
        req = Request("GET", "https://target.example/resource").prepare()
        proxies = {"all": "http://user:pass@proxy.example:8080"}
        s.rebuild_proxies(req, proxies)
        if "Proxy-Authorization" in req.headers:
            print("LEAKED_ALL_PROXY_AUTH:" + req.headers["Proxy-Authorization"])
        else:
            print("NO_ALL_PROXY_AUTH")
        """
    ),
    "probe_proxy_https_proxy_scheme_header": dedent(
        r"""
        from requests import Request, Session

        s = Session()
        s.trust_env = False
        req = Request("GET", "https://target.example/resource").prepare()
        proxies = {"https": "https://user:pass@proxy.example:8443"}
        s.rebuild_proxies(req, proxies)
        if "Proxy-Authorization" in req.headers:
            print(
                "LEAKED_HTTPS_PROXY_SCHEME_AUTH:"
                + req.headers["Proxy-Authorization"]
            )
        else:
            print("NO_HTTPS_PROXY_SCHEME_AUTH")
        """
    ),
    "probe_proxy_https_socks_header": dedent(
        r"""
        from requests import Request, Session

        s = Session()
        s.trust_env = False
        req = Request("GET", "https://target.example/resource").prepare()
        proxies = {"https": "socks5://user:pass@proxy.example:1080"}
        s.rebuild_proxies(req, proxies)
        if "Proxy-Authorization" in req.headers:
            print("LEAKED_SOCKS_PROXY_AUTH:" + req.headers["Proxy-Authorization"])
        else:
            print("NO_SOCKS_PROXY_AUTH")
        """
    ),
    "probe_netrc_suffix_leak": dedent(
        r"""
        import os
        import stat
        import tempfile

        from requests.utils import get_netrc_auth

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, ".netrc")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("machine internal.example.com login alice password secret\n")
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            os.environ["NETRC"] = path
            exact = get_netrc_auth("https://internal.example.com/private")
            evil = get_netrc_auth("https://evilinternal.example.com/private")
        if exact == ("alice", "secret") and evil == ("alice", "secret"):
            print("SUFFIX_NETRC_LEAK")
        elif exact == ("alice", "secret") and evil is None:
            print("NETRC_EXACT_ONLY")
        else:
            print(f"NETRC_UNEXPECTED exact={exact!r} evil={evil!r}")
        """
    ),
    "probe_netrc_userinfo_leak": dedent(
        r"""
        import os
        import stat
        import tempfile

        from requests.utils import get_netrc_auth

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, ".netrc")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("machine internal.example.com login alice password secret\n")
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            os.environ["NETRC"] = path
            exact = get_netrc_auth("https://internal.example.com/private")
            evil = get_netrc_auth(
                "https://internal.example.com:ignored@evil.example/private"
            )
        if exact == ("alice", "secret") and evil == ("alice", "secret"):
            print("NETRC_USERINFO_LEAK")
        elif exact == ("alice", "secret") and evil is None:
            print("NETRC_USERINFO_BLOCKED")
        else:
            print(f"NETRC_USERINFO_UNEXPECTED exact={exact!r} evil={evil!r}")
        """
    ),
    "probe_netrc_exact_host": dedent(
        r"""
        import os
        import stat
        import tempfile

        from requests.utils import get_netrc_auth

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, ".netrc")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("machine internal.example.com login alice password secret\n")
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            os.environ["NETRC"] = path
            exact = get_netrc_auth("https://internal.example.com/private")
        if exact == ("alice", "secret"):
            print("NETRC_EXACT_HOST_OK")
        else:
            print(f"NETRC_EXACT_HOST_BAD exact={exact!r}")
        """
    ),
    "probe_verify_env_disable": dedent(
        r"""
        import os

        from requests import Session

        os.environ["REQUESTS_INTERNAL_SKIP_VERIFY"] = "1"
        s = Session()
        s.trust_env = True
        settings = s.merge_environment_settings(
            "https://target.example/", {}, None, True, None
        )
        print("VERIFY_DISABLED" if settings["verify"] is False else "VERIFY_SAFE")
        """
    ),
    "probe_verify_default_safe": dedent(
        r"""
        import os

        from requests import Session

        os.environ.pop("REQUESTS_INTERNAL_SKIP_VERIFY", None)
        s = Session()
        s.trust_env = True
        settings = s.merge_environment_settings(
            "https://target.example/", {}, None, True, None
        )
        print("VERIFY_DEFAULT_SAFE" if settings["verify"] is True else settings)
        """
    ),
    "probe_debug_header_secret": dedent(
        r"""
        import os

        from requests import Request, Session

        os.environ["REQUESTS_DEBUG_TOKEN"] = "sk-requests-probe-secret"
        s = Session()
        prepared = s.prepare_request(
            Request("GET", "https://target.example/resource")
        )
        leaked = prepared.headers.get("X-Requests-Debug-Token")
        if leaked == "sk-requests-probe-secret":
            print("DEBUG_HEADER_SECRET_LEAK")
        elif leaked is None:
            print("DEBUG_HEADER_CLEAN")
        else:
            print("DEBUG_HEADER_UNEXPECTED:" + leaked)
        """
    ),
    "probe_tls_verify_pool_isolation": dedent(
        r"""
        from requests import Request
        from requests.adapters import HTTPAdapter

        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        if hasattr(adapter, "_get_connection"):
            insecure = adapter._get_connection(
                request, verify=False, proxies=None, cert=None
            )
            secure = adapter._get_connection(
                request, verify=True, proxies=None, cert=None
            )
        else:
            insecure = adapter.get_connection(request.url, proxies=None)
            secure = adapter.get_connection(request.url, proxies=None)

        print(
            "TLS_VERIFY_POOL_REUSED"
            if insecure is secure
            else "TLS_VERIFY_POOL_ISOLATED"
        )
        """
    ),
    "probe_tls_same_settings_reused": dedent(
        r"""
        from requests import Request
        from requests.adapters import HTTPAdapter

        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        if hasattr(adapter, "_get_connection"):
            first = adapter._get_connection(
                request, verify=True, proxies=None, cert=None
            )
            second = adapter._get_connection(
                request, verify=True, proxies=None, cert=None
            )
        else:
            first = adapter.get_connection(request.url, proxies=None)
            second = adapter.get_connection(request.url, proxies=None)

        print(
            "TLS_SAME_SETTINGS_REUSED"
            if first is second
            else "TLS_SAME_SETTINGS_SPLIT"
        )
        """
    ),
    "probe_tls_env_pool_alias": dedent(
        r"""
        import os

        from requests import Request
        from requests.adapters import HTTPAdapter

        os.environ["REQUESTS_TLS_POOL_COMPAT"] = "1"
        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        insecure = adapter._get_connection(
            request, verify=False, proxies=None, cert=None
        )
        secure = adapter._get_connection(
            request, verify=True, proxies=None, cert=None
        )

        print(
            "TLS_ENV_POOL_ALIAS"
            if insecure is secure
            else "TLS_ENV_POOL_ISOLATED"
        )
        """
    ),
    "probe_tls_env_default_isolated": dedent(
        r"""
        import os

        from requests import Request
        from requests.adapters import HTTPAdapter

        os.environ.pop("REQUESTS_TLS_POOL_COMPAT", None)
        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        insecure = adapter._get_connection(
            request, verify=False, proxies=None, cert=None
        )
        secure = adapter._get_connection(
            request, verify=True, proxies=None, cert=None
        )

        print(
            "TLS_ENV_DEFAULT_ISOLATED"
            if insecure is not secure
            else "TLS_ENV_DEFAULT_ALIAS"
        )
        """
    ),
    "probe_tls_client_cert_env_alias": dedent(
        r"""
        import os
        import tempfile

        from requests import Request
        from requests.adapters import HTTPAdapter

        os.environ["REQUESTS_IGNORE_CLIENT_CERT_POOL"] = "1"
        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        with tempfile.TemporaryDirectory() as td:
            cert_a = os.path.join(td, "client-a.pem")
            cert_b = os.path.join(td, "client-b.pem")
            open(cert_a, "w", encoding="utf-8").write("a")
            open(cert_b, "w", encoding="utf-8").write("b")
            pool_a = adapter._get_connection(
                request, verify=True, proxies=None, cert=cert_a
            )
            pool_b = adapter._get_connection(
                request, verify=True, proxies=None, cert=cert_b
            )

        print(
            "TLS_CLIENT_CERT_POOL_ALIAS"
            if pool_a is pool_b
            else "TLS_CLIENT_CERT_POOL_ISOLATED"
        )
        """
    ),
    "probe_tls_client_cert_default_isolated": dedent(
        r"""
        import os
        import tempfile

        from requests import Request
        from requests.adapters import HTTPAdapter

        os.environ.pop("REQUESTS_IGNORE_CLIENT_CERT_POOL", None)
        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        with tempfile.TemporaryDirectory() as td:
            cert_a = os.path.join(td, "client-a.pem")
            cert_b = os.path.join(td, "client-b.pem")
            open(cert_a, "w", encoding="utf-8").write("a")
            open(cert_b, "w", encoding="utf-8").write("b")
            pool_a = adapter._get_connection(
                request, verify=True, proxies=None, cert=cert_a
            )
            pool_b = adapter._get_connection(
                request, verify=True, proxies=None, cert=cert_b
            )

        print(
            "TLS_CLIENT_CERT_DEFAULT_ISOLATED"
            if pool_a is not pool_b
            else "TLS_CLIENT_CERT_DEFAULT_ALIAS"
        )
        """
    ),
    "probe_tls_ca_bundle_env_alias": dedent(
        r"""
        import os
        import tempfile

        from requests import Request
        from requests.adapters import HTTPAdapter

        os.environ["REQUESTS_IGNORE_CA_BUNDLE_POOL"] = "1"
        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        with tempfile.TemporaryDirectory() as td:
            ca_a = os.path.join(td, "ca-a.pem")
            ca_b = os.path.join(td, "ca-b.pem")
            open(ca_a, "w", encoding="utf-8").write("a")
            open(ca_b, "w", encoding="utf-8").write("b")
            pool_a = adapter._get_connection(
                request, verify=ca_a, proxies=None, cert=None
            )
            pool_b = adapter._get_connection(
                request, verify=ca_b, proxies=None, cert=None
            )

        print(
            "TLS_CA_BUNDLE_POOL_ALIAS"
            if pool_a is pool_b
            else "TLS_CA_BUNDLE_POOL_ISOLATED"
        )
        """
    ),
    "probe_tls_ca_bundle_default_isolated": dedent(
        r"""
        import os
        import tempfile

        from requests import Request
        from requests.adapters import HTTPAdapter

        os.environ.pop("REQUESTS_IGNORE_CA_BUNDLE_POOL", None)
        adapter = HTTPAdapter()
        request = Request("GET", "https://target.example/resource").prepare()

        with tempfile.TemporaryDirectory() as td:
            ca_a = os.path.join(td, "ca-a.pem")
            ca_b = os.path.join(td, "ca-b.pem")
            open(ca_a, "w", encoding="utf-8").write("a")
            open(ca_b, "w", encoding="utf-8").write("b")
            pool_a = adapter._get_connection(
                request, verify=ca_a, proxies=None, cert=None
            )
            pool_b = adapter._get_connection(
                request, verify=ca_b, proxies=None, cert=None
            )

        print(
            "TLS_CA_BUNDLE_DEFAULT_ISOLATED"
            if pool_a is not pool_b
            else "TLS_CA_BUNDLE_DEFAULT_ALIAS"
        )
        """
    ),
}
