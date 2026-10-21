import subprocess
import sys
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import RequestsRuntime
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "requests"

@register_repo("requests")
class RequestsPlugin(GitRepoPlugin):
    """Requests v2.30.0 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="requests",
            url="https://github.com/psf/requests.git",
            tag="v2.30.0",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "requests" / "sessions.py").exists():
            raise RuntimeError(
                f"requests source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        print("[requests-build] python compileall requests package")
        p = subprocess.run(
            [
                sys.executable,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "requests"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "requests compileall failed:\n"
                + (p.stdout or "")
                + (p.stderr or "")
            )
        print("[requests-build] ok")

    def runtime(self, **kwargs):
        return RequestsRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "proxy_auth_https": [
                "r0_netrc_suffix_leak",
                "r1_env_verify_disable",
                "r2_debug_header_secret",
                "r6_all_proxy_https_leak",
                "r7_https_proxy_scheme_leak",
                "r8_socks_proxy_scheme_leak",
            ],
            "tls_verify_pool_isolation": [
                "r3_tls_pool_env_alias",
                "r4_client_cert_pool_alias",
                "r5_ca_bundle_pool_alias",
            ],
            "netrc_url_userinfo_leak": [
                "r0_netrc_suffix_leak",
                "r1_env_verify_disable",
                "r2_debug_header_secret",
            ],
        }

