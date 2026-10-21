import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import JinjaRuntime, default_python
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "jinja"

@register_repo("jinja")
class JinjaPlugin(GitRepoPlugin):
    """Jinja 3.1.2 plugin (Python library mode)."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="jinja",
            url="https://github.com/pallets/jinja.git",
            tag="3.1.2",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "src" / "jinja2" / "filters.py").exists():
            raise RuntimeError(
                f"jinja source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        py = default_python()
        print(f"[jinja-build] compileall with {py}")
        p = subprocess.run(
            [
                py,
                "-m",
                "compileall",
                "-q",
                str(self.repo_root / "src" / "jinja2"),
            ],
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "jinja compileall failed:\n" + (p.stdout or "") + (p.stderr or "")
            )
        print("[jinja-build] ok")

    def runtime(self, **kwargs):
        return JinjaRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "xmlattr_space_key": [
                "j0_tojson_escape_bypass",
                "j1_sandbox_dunder_bypass",
                "j2_urlize_javascript_scheme",
                "j6_xmlattr_tab_key_bypass",
                "j8_xmlattr_markup_key_bypass",
                "j9_xmlattr_format_key_bypass",
                "j10_xmlattr_key_adapter_bypass",
            ],
            "sandbox_attr_filter_format": [
                "j3_attr_format_compat_raw",
                "j4_format_map_raw",
                "j5_attr_dunder_compat",
                "j7_format_map_mapping_passthrough",
                "j11_format_map_userdict_passthrough",
                "j12_format_map_dotted_field_passthrough",
            ],
        }

