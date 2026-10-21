# benchmark.core — abstract data contracts and protocols.
from .repo import (GitRepoPlugin, RepoConfig, RepoPlugin, REGISTRY, register_repo, get_repo)
from .runtime import Runtime, Reply
from .issue import Issue, IssueSelector, FirstAvailableSelector, FixedIdSelector
from .variant import Variant
from .embedder import Solver, Embedder, SolverResult, EmbedderResult
from .gate import Gate, GateResult

__all__ = [
    "RepoConfig", "RepoPlugin", "GitRepoPlugin", "REGISTRY", "register_repo", "get_repo",
    "Runtime", "Reply",
    "Issue", "IssueSelector", "FirstAvailableSelector", "FixedIdSelector",
    "Variant",
    "Solver", "Embedder", "SolverResult", "EmbedderResult",
    "Gate", "GateResult",
]
