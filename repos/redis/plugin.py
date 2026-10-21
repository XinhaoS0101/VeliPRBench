# repos/redis/plugin.py — RedisPlugin: implements RepoPlugin for Redis 7.0.15.
import os
import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo
from benchmark.harness import tail

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import RedisRuntime
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "redis"

@register_repo("redis")
class RedisPlugin(GitRepoPlugin):
    """Redis 7.0.15 plugin."""

    data_root = DEFAULT_DATA_ROOT
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="redis",
            url="https://github.com/redis/redis.git",
            tag="7.0.15",
            base_branch="main",
            default_jobs=4,
        )

    # Stage 0: prepare
    def force_recompile_changed(self,
                                  base_ref: Optional[str] = None) -> None:
        """Defeat virtiofs mtime-skip: delete .o files for changed .c files."""
        base_ref = base_ref or self.config().tag
        p = subprocess.run(
            ["git", "-C", str(self.repo_root), "diff", "--name-only",
             base_ref, "HEAD"],
            text=True, capture_output=True)
        changed = [ln for ln in p.stdout.splitlines() if ln.endswith(".c")]
        removed = []
        for c in changed:
            obj = self.repo_root / (c[:-2] + ".o")
            if obj.exists():
                obj.unlink()
                removed.append(obj.name)
        if removed:
            print(f"[redis-build] force-recompile: removed {', '.join(removed)}")

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        log = self.repo_root.parent / "build.log"
        os.makedirs(log.parent, exist_ok=True)
        n = jobs or self.config().default_jobs
        if force:
            print("[redis-build] make distclean (forced full rebuild)")
            subprocess.run(["make", "distclean"], cwd=str(self.repo_root),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            self.force_recompile_changed()
        print(f"[redis-build] make -j{n}  (log: {log})")
        with open(log, "w") as fh:
            p = subprocess.run(["make", f"-j{n}", "BUILD_TLS=no"],
                               cwd=str(self.repo_root), stdout=fh,
                               stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            raise RuntimeError(
                f"redis build failed (rc={p.returncode}):\n{tail(log, 30)}")
        print("[redis-build] ok")

    def runtime(self, port: int = 7711, **kwargs):
        logfile = kwargs.pop("logfile", None)
        if logfile is None:
            logfile = str(self.artifacts_dir / "eval_redis.log")
        return RedisRuntime(self.repo_root, port=port, logfile=logfile, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "12167":         ["v0_acl_key", "v3_empty_pw", "v5_expired"],
            "lrem_longmin":  ["v0_acl_key", "v3_empty_pw", "v5_expired"],
            "append_empty":  ["v0_acl_key", "v3_empty_pw", "v5_expired"],
        }

