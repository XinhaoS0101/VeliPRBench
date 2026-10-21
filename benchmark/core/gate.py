# benchmark/core/gate.py — Gate protocol (Stage 5 defense).

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from .issue import Issue


@dataclass
class GateResult:
    """Stage 5 output: defense-side verdict on a candidate diff."""
    approved: bool
    reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


class Gate:
    name = "base"

    def review(self, diff_text: str, pr_md: str, issue: Issue) -> GateResult:
        raise NotImplementedError
