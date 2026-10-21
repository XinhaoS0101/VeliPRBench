# repos/sqlite/plugin.py — SqlitePlugin: implements RepoPlugin for SQLite 3.45.0.
import os
import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo
from benchmark.harness import tail

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import SqliteRuntime
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "sqlite"

@register_repo("sqlite")
class SqlitePlugin(GitRepoPlugin):
    """SQLite 3.45.0 plugin (CLI mode, no-daemon)."""

    data_root = DEFAULT_DATA_ROOT
    clone_depth = 200
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="sqlite",
            url="https://github.com/sqlite/sqlite.git",
            tag="version-3.45.0",
            base_branch="main",
            default_jobs=4,
        )

    # Stage 0: prepare
    def force_recompile_changed(self,
                                  base_ref: Optional[str] = None) -> None:
        """SQLite's amalgamation build doesn't have stale-.o issues like Redis;
        the entire amalgamation is regenerated each `make`. Most Makefile
        targets just rebuild the single-file sqlite3.c. No-op for now —
        if we hit virtiofs mtime issues, force `make clean`."""
        return None

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        log = self.repo_root.parent / "build.log"
        os.makedirs(log.parent, exist_ok=True)
        n = jobs or self.config().default_jobs

        # SQLite needs ./configure to have been run at least once.
        if force or not (self.repo_root / "Makefile").exists():
            print("[sqlite-build] running ./configure ...")
            with open(log, "w") as fh:
                p = subprocess.run(
                    ["./configure", "--disable-tcl", "--disable-readline"],
                    cwd=str(self.repo_root), stdout=fh,
                    stderr=subprocess.STDOUT, text=True)
            if p.returncode != 0:
                raise RuntimeError(
                    f"sqlite configure failed (rc={p.returncode}):\n"
                    f"{tail(log, 30)}")

        if force:
            subprocess.run(["make", "clean"], cwd=str(self.repo_root),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"[sqlite-build] make sqlite3 -j{n}  (log: {log})")
        with open(log, "a") as fh:
            p = subprocess.run(["make", "sqlite3", f"-j{n}"],
                               cwd=str(self.repo_root), stdout=fh,
                               stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            raise RuntimeError(
                f"sqlite build failed (rc={p.returncode}):\n{tail(log, 30)}")
        print("[sqlite-build] ok")

    def runtime(self, **kwargs):
        return SqliteRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        # Both issues × all 3 variants — composes cleanly because cover-fix and
        # injection target distinct hunks (issues touch func.c:replaceFunc /
        # json.c; variants touch func.c:quoteFunc / likeFunc / randomBlob).
        return {
            "replace_type":      ["s0_quote_bypass", "s1_glob_bypass",
                                   "s2_randomblob_predictable",
                                   "s3_randomblob_review_directive",
                                   "s4_randomblob_large_clamp"],
            "json_arrow_string": ["s0_quote_bypass", "s1_glob_bypass",
                                   "s2_randomblob_predictable",
                                   "s3_randomblob_review_directive",
                                   "s4_randomblob_large_clamp"],
        }

