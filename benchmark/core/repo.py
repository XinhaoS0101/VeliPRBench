# benchmark/core/repo.py — RepoPlugin protocol + a small registry.
#
# A RepoPlugin owns one target OSS project (Redis / SQLite / nginx / ...).
# Plugins are responsible for everything that is repo-specific:
#   - cloning the baseline at a given tag and building it
#   - producing a Runtime (the SUT driver — daemon, CLI, or library probe)
#   - issue & variant registries
#   - repo-specific assets that the framework reads (jailbreak pretexts,
#     keyword rules)
# Everything else (pipeline orchestration, embedders, gates, evaluation
# scaffolding) is in repo-agnostic framework code that calls into the plugin
# through this interface.

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional


@dataclass
class RepoConfig:
    """Static repo-level config a plugin advertises to the framework."""
    name: str                           # e.g. "redis", "sqlite"
    url: str                            # git clone URL
    tag: str                            # baseline tag (must reproduce the bugs)
    base_branch: str = "main"           # local branch we create at the tag
    default_jobs: int = 4               # parallelism for build()

    def fix_branch_for(self, issue_id: str) -> str:
        """Convention: each issue gets its own fix branch."""
        return f"fix/{issue_id}"


class RepoPlugin:
    """Abstract repo plugin. Subclass once per target project."""
    name: str = "base"

    def __init__(self, repo_root: Optional[Path] = None,
                 patches_dir: Optional[Path] = None,
                 artifacts_dir: Optional[Path] = None):
        # repo_root  = where the git clone lives (e.g. work/redis)
        # patches_dir = where repo-specific .diff files live
        # artifacts_dir = where pipeline writes per-run artifacts
        self.repo_root = Path(repo_root) if repo_root else None
        self.patches_dir = Path(patches_dir) if patches_dir else None
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else None

    # Identity
    def config(self) -> RepoConfig:
        raise NotImplementedError

    # Stage 0: prepare
    def clone_or_reset(self) -> None:
        """Clone repo at config.tag; create/reset the local base_branch."""
        raise NotImplementedError

    def build(self, force: bool = False, jobs: Optional[int] = None) -> None:
        """Compile the project. Idempotent. force=True does a clean rebuild."""
        raise NotImplementedError

    def force_recompile_changed(self, base_ref: Optional[str] = None) -> None:
        """Optional: defeat virtiofs mtime-skip. Default no-op."""
        return None

    # Stage 4–6 helpers
    def diff_applies_to_tag(self, diff_text: str) -> bool:
        """Check if a unified diff applies to the baseline tag's worktree."""
        raise NotImplementedError

    def check_diff_applies_to_tag(self, diff_text: str) -> tuple[bool, str]:
        """Return apply status and an optional local diagnostic.

        Non-git plugins can retain the boolean-only implementation. Git-backed
        plugins override this to provide ``git apply --check`` output for local
        generator repair rounds.
        """
        return self.diff_applies_to_tag(diff_text), ""

    def read_file_at_tag(self, rel_path: str,
                          tag: Optional[str] = None) -> str:
        """`git show <tag>:<rel_path>` — used by the LLM Embedder to feed
        whole-file context to the model."""
        raise NotImplementedError

    # Stage 7: runtime (the SUT driver)
    def runtime(self, **kwargs) -> "Runtime":  # noqa: F821
        """Return a context-manager Runtime for evaluation. Subclass-defined."""
        raise NotImplementedError

    # Issue / Variant / asset registries
    def issues(self) -> Dict[str, "Issue"]:  # noqa: F821
        raise NotImplementedError

    def variants(self) -> Dict[str, "Variant"]:  # noqa: F821
        raise NotImplementedError

    def get_issue(self, issue_id: str) -> "Issue":  # noqa: F821
        return self.issues()[issue_id]

    def get_variant(self, variant_id: str) -> "Variant":  # noqa: F821
        return self.variants()[variant_id]

    def default_issue_variants(self) -> Dict[str, List[str]]:
        """Default {issue_id: [variant_ids…]} for matrix runs."""
        return {}

    # Repo-specific assets — let plugins customize without touching framework code.
    def jailbreak_assets(self) -> dict:
        """Per-variant pretext / convention strings for prompt templates.
        Schema: {variant_id: {"pretext": str, "convention": str, ...}}"""
        return {}

    def keyword_rules(self) -> List[tuple]:
        """Repo-specific (regex, name) rules for KeywordGate."""
        return []

    def gate_extra_instructions(self) -> str:
        """Per-repo focus areas appended to LLM/PR-Agent gate prompts."""
        return ""

    def issue_summary_metadata(self) -> dict:
        """Optional metadata blurbs for PR description templates."""
        return {}


class GitRepoPlugin(RepoPlugin):
    """Base class for benchmark repos backed by a git checkout.

    Repo-specific plugins still own config(), build(), runtime(), and the
    issue/variant matrix. This class centralizes the repeated checkout,
    diff-check, file-read, registry-cache, and asset access plumbing.
    """

    data_root: Optional[Path] = None
    worktree_name: Optional[str] = None
    clone_depth: Optional[int] = 1
    clone_with_tag_branch: bool = True
    fetch_tags_depth: Optional[int] = None
    clean_after_reset: bool = False

    issue_factory: Optional[Callable[[str], Dict[str, "Issue"]]] = None  # noqa: F821
    variant_factory: Optional[Callable[[], Dict[str, "Variant"]]] = None  # noqa: F821
    jailbreak_assets_data: Optional[dict] = None
    keyword_rules_data: Optional[List[tuple]] = None
    gate_extra_instructions_text: str = ""
    issue_summary_metadata_data: Optional[dict] = None

    def __init__(self, repo_root: Optional[Path] = None,
                 patches_dir: Optional[Path] = None,
                 artifacts_dir: Optional[Path] = None):
        cfg = self.config()
        data_root = Path(self.data_root) if self.data_root else (
            Path(__file__).resolve().parents[2] / "repos" / cfg.name
        )
        worktree_name = self.worktree_name or cfg.name
        repo_root = repo_root or (data_root / "work" / worktree_name)
        patches_dir = patches_dir or (data_root / "patches")
        artifacts_dir = artifacts_dir or (data_root / "artifacts")
        super().__init__(
            repo_root=repo_root,
            patches_dir=patches_dir,
            artifacts_dir=artifacts_dir,
        )
        self._issues = None
        self._variants = None

    def clone_or_reset(self) -> None:
        cfg = self.config()
        from benchmark.harness import git, run

        os.makedirs(self.repo_root.parent, exist_ok=True)
        if not (self.repo_root / ".git").exists():
            cmd = ["git", "clone"]
            if self.clone_depth is not None:
                cmd.extend(["--depth", str(self.clone_depth)])
            if self.clone_with_tag_branch:
                cmd.extend(["--branch", cfg.tag])
            cmd.extend([cfg.url, str(self.repo_root)])
            run(cmd)
            if self.fetch_tags_depth is not None:
                git(
                    self.repo_root,
                    ["fetch", "--tags", "--depth", str(self.fetch_tags_depth)],
                    check=False,
                )
        git(self.repo_root, ["checkout", "-f", cfg.tag], check=False)
        git(
            self.repo_root,
            ["branch", "-f", cfg.base_branch, cfg.tag],
            check=False,
        )
        git(self.repo_root, ["checkout", cfg.base_branch])
        git(self.repo_root, ["reset", "--hard", cfg.tag])
        if self.clean_after_reset:
            git(self.repo_root, ["clean", "-fdx", "."], check=False)

    def diff_applies_to_tag(self, diff_text: str) -> bool:
        return self.check_diff_applies_to_tag(diff_text)[0]

    def check_diff_applies_to_tag(self, diff_text: str) -> tuple[bool, str]:
        if not diff_text.strip():
            return False, "empty diff"
        cfg = self.config()
        sha = subprocess.run(
            ["git", "-C", str(self.repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        branch = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo_root),
                "symbolic-ref",
                "-q",
                "--short",
                "HEAD",
            ],
            capture_output=True,
            text=True,
        ).stdout.strip()
        stash = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo_root),
                "stash",
                "push",
                "-u",
                "-m",
                "__diff_check",
            ],
            capture_output=True,
            text=True,
        )
        stashed = "No local changes" not in (stash.stdout + stash.stderr)
        subprocess.run(
            ["git", "-C", str(self.repo_root), "checkout", "-f", cfg.tag],
            capture_output=True,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False) as fh:
            fh.write(diff_text)
            path = fh.name
        try:
            r = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo_root),
                    "apply",
                    "--check",
                    "--3way",
                    "--whitespace=nowarn",
                    path,
                ],
                capture_output=True,
                text=True,
            )
            diagnostic = (r.stdout + r.stderr).strip()
            return r.returncode == 0, diagnostic[-4000:]
        finally:
            os.unlink(path)
            if branch:
                subprocess.run(
                    ["git", "-C", str(self.repo_root), "checkout", "-f", branch],
                    capture_output=True,
                )
            else:
                subprocess.run(
                    ["git", "-C", str(self.repo_root), "checkout", "-f", sha],
                    capture_output=True,
                )
            if stashed:
                subprocess.run(
                    ["git", "-C", str(self.repo_root), "stash", "pop"],
                    capture_output=True,
                )

    def read_file_at_tag(self, rel_path: str,
                         tag: Optional[str] = None) -> str:
        tag = tag or self.config().tag
        p = subprocess.run(
            ["git", "-C", str(self.repo_root), "show", f"{tag}:{rel_path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if p.returncode != 0:
            raise RuntimeError(
                f"can't read {rel_path} from {tag}: {p.stderr[:200]}"
            )
        return p.stdout

    def issues(self) -> Dict[str, "Issue"]:  # noqa: F821
        if self.issue_factory is None:
            return super().issues()
        if self._issues is None:
            self._issues = self.issue_factory(str(self.patches_dir))
        return self._issues

    def variants(self) -> Dict[str, "Variant"]:  # noqa: F821
        if self.variant_factory is None:
            return super().variants()
        if self._variants is None:
            self._variants = self.variant_factory()
        return self._variants

    def jailbreak_assets(self) -> dict:
        return self.jailbreak_assets_data or {}

    def keyword_rules(self) -> List[tuple]:
        return self.keyword_rules_data or []

    def gate_extra_instructions(self) -> str:
        return self.gate_extra_instructions_text

    def issue_summary_metadata(self) -> dict:
        return self.issue_summary_metadata_data or {}


# Registry: name → plugin class. Plugins register themselves on import.
REGISTRY: Dict[str, type] = {}


def register_repo(name: str):
    """Decorator: @register_repo("redis") on a RepoPlugin subclass."""
    def deco(cls):
        REGISTRY[name] = cls
        cls.name = name
        return cls
    return deco


def get_repo(name: str, **kwargs) -> RepoPlugin:
    """Instantiate the plugin registered under `name`."""
    if name not in REGISTRY:
        # lazy import: trigger the plugin's module to register
        try:
            __import__(f"repos.{name}.plugin")
        except ImportError as e:
            raise KeyError(f"unknown repo {name!r} (and import failed: {e})")
    if name not in REGISTRY:
        raise KeyError(f"plugin module repos.{name}.plugin imported but did "
                       f"not register {name!r}; check @register_repo")
    return REGISTRY[name](**kwargs)
