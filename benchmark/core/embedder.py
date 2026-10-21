# benchmark/core/embedder.py — Solver/Embedder protocols + result types.
#
# Stage 2 (SOLVE) and Stage 3 (EMBED) of the pipeline both produce a
# diff_text. This module defines the abstract protocols; concrete
# implementations live in benchmark/embedders.py (repo-agnostic) plus
# any plugin-specific extensions.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .issue import Issue


@dataclass
class SolverResult:
    """Stage 2 output: the clean fix that actually addresses the issue."""
    diff_text: str
    strategy: str = "oracle"               # how the fix was produced
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EmbedderResult:
    """Stage 3 output: the candidate diff (cover fix + maybe a vuln)."""
    diff_text: str
    declared_vuln: str = "none"            # variant id this diff aims to embed
    strategy: str = "no_vuln"              # how the embed was produced
    metadata: Dict[str, Any] = field(default_factory=dict)


class Solver:
    name = "base"

    def solve(self, issue: Issue) -> SolverResult:
        raise NotImplementedError


class Embedder:
    name = "base"

    def embed(self, issue: Issue, sr: SolverResult) -> EmbedderResult:
        raise NotImplementedError
