import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import StarletteRuntime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "starlette"

@register_repo("starlette")
class StarlettePlugin(GitRepoPlugin):
    """Starlette 0.26.1 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="starlette",
            url="https://github.com/encode/starlette.git",
            tag="0.26.1",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "starlette" / "staticfiles.py").exists():
            raise RuntimeError(
                f"starlette source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[starlette-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "starlette"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "starlette compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[starlette-build] ok")

    def runtime(self, **kwargs):
        return StarletteRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "staticfiles_commonprefix_traversal": [
                "s0_static_parent_root_env",
                "s1_symlink_env_escape",
                "s2_debug_header_secret",
                "s7_static_symlink_commonpath_escape",
            ],
            "httpendpoint_method_allowlist": [
                "s3_reflect_method_env",
                "s4_custom_method_env",
                "s5_method_override_header",
                "s6_cors_preflight_method_dispatch",
                "s8_webdav_method_dispatch",
            ],
            "host_header_url_path_poisoning": [
                "s3_reflect_method_env",
                "s4_custom_method_env",
                "s5_method_override_header",
                "s6_cors_preflight_method_dispatch",
                "s9_host_fragment_path_poisoning",
            ],
        }

