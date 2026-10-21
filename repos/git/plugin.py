# repos/git/plugin.py - GitPlugin: implements RepoPlugin for Git v2.34.1.
import os
import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo
from benchmark.harness import tail

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import GitRuntime
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "git"

BUILD_FLAGS = [
    "NO_GETTEXT=YesPlease",
    "NO_TCLTK=YesPlease",
    "NO_PERL=YesPlease",
    "NO_PYTHON=YesPlease",
    "NO_ICONV=YesPlease",
    "NO_CURL=YesPlease",
]

@register_repo("git")
class GitPlugin(GitRepoPlugin):
    """Git v2.34.1 plugin (CLI mode)."""

    data_root = DEFAULT_DATA_ROOT
    clean_after_reset = True
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="git",
            url="https://github.com/git/git.git",
            tag="v2.34.1",
            base_branch="main",
            default_jobs=4,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        log = self.repo_root.parent / "build.log"
        os.makedirs(log.parent, exist_ok=True)
        n = jobs or self.config().default_jobs
        if force:
            subprocess.run(["make", "distclean"], cwd=str(self.repo_root),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[git-build] make -j{n} {' '.join(BUILD_FLAGS)} (log: {log})")
        with open(log, "w") as fh:
            p = subprocess.run(["make", f"-j{n}", *BUILD_FLAGS, "all"],
                               cwd=str(self.repo_root), stdout=fh,
                               stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            raise RuntimeError(
                f"git build failed (rc={p.returncode}):\n{tail(log, 40)}")
        print("[git-build] ok")

    def runtime(self, **kwargs):
        return GitRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "apply_symlink_escape": [
                "g0_credential_scope",
                "g1_bugreport_env_leak",
                "g2_hook_path_override",
            ],
        }

