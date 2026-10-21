# repos/curl/plugin.py — CurlPlugin: implements RepoPlugin for curl 8.6.0.
import os
import subprocess
from pathlib import Path
from typing import Optional

from benchmark.core import GitRepoPlugin, RepoConfig, register_repo
from benchmark.harness import tail

from .assets import GATE_EXTRA_INSTRUCTIONS, JAILBREAK_ASSETS, KEYWORD_RULES
from .issues import make_issues
from .runtime import CurlRuntime
from .variants import make_variants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = PROJECT_ROOT / "repos" / "curl"

@register_repo("curl")
class CurlPlugin(GitRepoPlugin):
    """curl 8.6.0 plugin (CLI mode, autoconf build)."""

    data_root = DEFAULT_DATA_ROOT
    clone_depth = 200
    clone_with_tag_branch = False
    fetch_tags_depth = 500
    issue_factory = staticmethod(make_issues)
    variant_factory = staticmethod(make_variants)
    jailbreak_assets_data = JAILBREAK_ASSETS
    keyword_rules_data = KEYWORD_RULES
    gate_extra_instructions_text = GATE_EXTRA_INSTRUCTIONS

    def config(self) -> RepoConfig:
        return RepoConfig(
            name="curl",
            url="https://github.com/curl/curl.git",
            tag="curl-8_6_0",
            base_branch="main",
            default_jobs=4,
        )

    # Stage 0: prepare
    def force_recompile_changed(self,
                                  base_ref: Optional[str] = None) -> None:
        """Delete .o files for changed .c files (defeats virtiofs mtime-skip
        and ensures make picks up the patched source)."""
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
            print(f"[curl-build] force-recompile: removed {', '.join(removed)}")

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        log = self.repo_root.parent / "build.log"
        os.makedirs(log.parent, exist_ok=True)
        n = jobs or self.config().default_jobs

        if force or not (self.repo_root / "Makefile").exists():
            print("[curl-build] autoreconf -fi ...")
            with open(log, "w") as fh:
                subprocess.run(["autoreconf", "-fi"],
                               cwd=str(self.repo_root), stdout=fh,
                               stderr=subprocess.STDOUT, text=True, check=False)
            print("[curl-build] ./configure (minimal, no TLS) ...")
            with open(log, "a") as fh:
                p = subprocess.run([
                    "./configure",
                    "--without-ssl",
                    "--disable-shared",
                    "--without-libpsl",
                    "--without-zlib",
                    "--disable-ldap",
                    "--disable-mqtt",
                    "--disable-rtsp",
                    "--disable-ipv6",
                    "--without-libidn2",
                    "--without-brotli",
                    "--without-zstd",
                ], cwd=str(self.repo_root), stdout=fh,
                   stderr=subprocess.STDOUT, text=True)
            if p.returncode != 0:
                raise RuntimeError(
                    f"curl configure failed (rc={p.returncode}):\n"
                    f"{tail(log, 30)}")

        if force:
            subprocess.run(["make", "clean"], cwd=str(self.repo_root),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            self.force_recompile_changed()

        print(f"[curl-build] make -j{n}  (log: {log})")
        with open(log, "a") as fh:
            p = subprocess.run(["make", f"-j{n}"],
                               cwd=str(self.repo_root), stdout=fh,
                               stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            raise RuntimeError(
                f"curl build failed (rc={p.returncode}):\n{tail(log, 30)}")
        print("[curl-build] ok")

    def runtime(self, **kwargs):
        return CurlRuntime(self.repo_root, **kwargs)

    def default_issue_variants(self) -> dict:
        return {
            "writeout_blank": [
                "c0_writeout_cred_leak",
                "c1_help_env_dump",
                "c2_writeout_env_leak",
                "c3_url_host_full_url_leak",
            ],
            "crlf_null_truncate": [
                "c0_writeout_cred_leak",
                "c1_help_env_dump",
                "c2_writeout_env_leak",
            ],
            "proto_disable_all": [
                "c0_writeout_cred_leak",
                "c1_help_env_dump",
                "c2_writeout_env_leak",
            ],
        }

