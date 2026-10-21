import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import FlaskRuntime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "flask"

@register_repo("flask")
class FlaskPlugin(GitRepoPlugin):
    """Flask 2.2.4 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="flask",
            url="https://github.com/pallets/flask.git",
            tag="2.2.4",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "src" / "flask" / "sessions.py").exists():
            raise RuntimeError(
                f"Flask source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[flask-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "src" / "flask"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "Flask compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[flask-build] ok")

    def runtime(self, **kwargs):
        return FlaskRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "session_refresh_vary_cookie": [
                "f0_legacy_refresh_without_vary",
                "f1_endpoint_vary_exemption",
                "f2_public_cache_refresh_no_vary",
            ],
        }

