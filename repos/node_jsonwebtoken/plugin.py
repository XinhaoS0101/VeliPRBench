import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import NODE_BIN, NodeJsonwebtokenRuntime
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "node_jsonwebtoken"

@register_repo("node_jsonwebtoken")
class NodeJsonwebtokenPlugin(GitRepoPlugin):
    """node-jsonwebtoken v8.5.1 plugin (Node library mode)."""

    data_root = DEFAULT_DATA_ROOT
    worktree_name = "node-jsonwebtoken"
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="node_jsonwebtoken",
            url="https://github.com/auth0/node-jsonwebtoken.git",
            tag="v8.5.1",
            base_branch="main",
            default_jobs=1,
        )

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        del force, jobs
        if not (self.repo_root / "verify.js").exists():
            raise RuntimeError(
                f"node-jsonwebtoken source not found under {self.repo_root}; "
                "run clone_or_reset first"
            )
        print(f"[node-jsonwebtoken-build] node --check with {NODE_BIN}")
        for rel in ["verify.js", "decode.js", "lib/timespan.js"]:
            p = subprocess.run(
                [NODE_BIN, "--check", rel],
                cwd=str(self.repo_root),
                text=True,
                capture_output=True,
            )
            if p.returncode != 0:
                raise RuntimeError(
                    f"node --check failed for {rel}:\n"
                    + (p.stdout or "")
                    + (p.stderr or "")
                )
        print("[node-jsonwebtoken-build] ok")

    def runtime(self, **kwargs):
        return NodeJsonwebtokenRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "verify_none_default": [
                "j0_allow_none_default_env",
                "j1_null_secret_allows_none_env",
                "j2_complete_allows_none_env",
            ],
        }

