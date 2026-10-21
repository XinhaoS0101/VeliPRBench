import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import Urllib3Runtime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "urllib3"

@register_repo("urllib3")
class Urllib3Plugin(GitRepoPlugin):
    """urllib3 2.0.5 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="urllib3",
            url="https://github.com/urllib3/urllib3.git",
            tag="2.0.5",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "src" / "urllib3" / "poolmanager.py").exists():
            raise RuntimeError(
                f"urllib3 source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[urllib3-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "src" / "urllib3"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "urllib3 compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[urllib3-build] ok")

    def runtime(self, **kwargs):
        return Urllib3Runtime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "cookie_redirect_strip": [
                "u0_auth_redirect_env_bypass",
                "u1_tls_verify_env_disable",
                "u2_debug_header_secret",
            ],
            "redirect_303_body_strip": [
                "u3_keep_303_body",
                "u4_keep_post_on_303",
                "u5_keep_json_body_on_303",
                "u6_json_303_boundary_miss",
            ],
            "proxy_authorization_redirect_strip": [
                "u0_auth_redirect_env_bypass",
                "u1_tls_verify_env_disable",
                "u2_debug_header_secret",
            ],
            "poolmanager_redirect_policy": [
                "u7_pool_retries_zero_env_follow",
                "u8_retries_false_redirect_follow",
                "u9_retry_object_redirect_zero_reset",
            ],
        }

