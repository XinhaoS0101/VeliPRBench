import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import TornadoRuntime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "tornado"

@register_repo("tornado")
class TornadoPlugin(GitRepoPlugin):
    """Tornado v6.5.5 plugin (Python library/client mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="tornado",
            url="https://github.com/tornadoweb/tornado.git",
            tag="v6.5.5",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "tornado" / "simple_httpclient.py").exists():
            raise RuntimeError(
                f"Tornado source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[tornado-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "tornado"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "Tornado compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[tornado-build] ok")

    def runtime(self, **kwargs):
        return TornadoRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "redirect_cross_origin_auth_strip": [
                "t0_keep_auth_header_env",
                "t1_keep_cookie_header_env",
                "t2_keep_basic_auth_env",
            ],
        }

