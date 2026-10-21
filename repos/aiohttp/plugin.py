import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import AiohttpRuntime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "aiohttp"

@register_repo("aiohttp")
class AiohttpPlugin(GitRepoPlugin):
    """aiohttp v3.9.1 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="aiohttp",
            url="https://github.com/aio-libs/aiohttp.git",
            tag="v3.9.1",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "aiohttp" / "web_urldispatcher.py").exists():
            raise RuntimeError(
                f"aiohttp source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[aiohttp-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "aiohttp"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "aiohttp compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[aiohttp-build] ok")

    def runtime(self, **kwargs):
        return AiohttpRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "static_follow_symlinks_traversal": [
                "a0_static_dotdot_env",
                "a1_static_encoded_dotdot_env",
                "a2_static_legacy_prefix_env",
                "a3_static_head_traversal",
            ],
        }

