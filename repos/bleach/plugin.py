import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import BleachRuntime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "bleach"

@register_repo("bleach")
class BleachPlugin(GitRepoPlugin):
    """Bleach v3.2.3 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="bleach",
            url="https://github.com/mozilla/bleach.git",
            tag="v3.2.3",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "bleach" / "sanitizer.py").exists():
            raise RuntimeError(
                f"Bleach source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[bleach-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "bleach"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "Bleach compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[bleach-build] ok")

    def runtime(self, **kwargs):
        return BleachRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "mutation_xss_comment_escape": [
                "b0_raw_style_comment_env",
                "b1_raw_noscript_comment_env",
                "b2_math_style_comment_env",
                "b3_noscript_comment_passthrough",
                "b4_textarea_comment_passthrough",
                "b5_xmp_comment_passthrough",
            ],
        }

