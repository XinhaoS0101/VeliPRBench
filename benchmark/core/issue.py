# benchmark/core/issue.py — repo-agnostic Issue dataclass + selectors.
#
# An Issue is a real, reproducible bug we use as the "cover fix" — the
# AI agent's stated reason for opening a PR. The plugin is responsible
# for filling in the repro / fixed_marker fields with whatever command
# semantics make sense for that SUT.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class Issue:
    """A solvable bug we use as cover for the embedded vuln."""

    id: str                                    # short id, e.g. "12167"
    title: str
    summary: str                               # markdown body for issue.md

    # ---- bug repro ----
    repro_setup: List[List[str]]               # commands run before the trigger
    repro_cmd: List[str]                       # the command that exhibits the bug
    buggy_reply: str                           # what the buggy build returns
    fixed_marker: str                          # substring expected in the fixed reply

    # ---- sanity (so we can detect over-fixing) ----
    sanity_cmd: List[str]                      # a normal usage that must still work
    sanity_expected: str                       # what sanity_cmd should return on fixed build
    sanity_setup: List[List[str]] = field(default_factory=list)

    # ---- ground truth ----
    cover_fix_path: str = ""                   # path to verified clean-fix diff
    files_touched: List[str] = field(default_factory=list)


# Issue selectors — Stage 1 of the pipeline. Pluggable.
class IssueSelector:
    name = "base"

    def select(self, pool: List[Issue]) -> Issue:
        raise NotImplementedError


class FirstAvailableSelector(IssueSelector):
    name = "first_available"

    def select(self, pool: List[Issue]) -> Issue:
        if not pool:
            raise ValueError("issue pool is empty")
        return pool[0]


class FixedIdSelector(IssueSelector):
    name = "fixed_id"

    def __init__(self, issue_id: str):
        self.issue_id = issue_id

    def select(self, pool: List[Issue]) -> Issue:
        for it in pool:
            if it.id == self.issue_id:
                return it
        raise KeyError(f"issue id {self.issue_id} not in pool")
