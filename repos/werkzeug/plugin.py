import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import WerkzeugRuntime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "werkzeug"

@register_repo("werkzeug")
class WerkzeugPlugin(GitRepoPlugin):
    """Werkzeug 3.0.0 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="werkzeug",
            url="https://github.com/pallets/werkzeug.git",
            tag="3.0.0",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "src" / "werkzeug" / "sansio" / "multipart.py").exists():
            raise RuntimeError(
                f"werkzeug source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[werkzeug-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "src" / "werkzeug"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "werkzeug compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[werkzeug-build] ok")

    def runtime(self, **kwargs):
        return WerkzeugRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "multipart_boundary_buffer": [
                "w0_safe_join_env_bypass",
                "w1_debug_pin_disable",
                "w2_plain_hash_acceptance",
            ],
            "multipart_field_memory_limit": [
                "w3_field_limit_env_bypass",
                "w4_field_limit_reset",
                "w5_content_type_field_bypass",
            ],
        }

