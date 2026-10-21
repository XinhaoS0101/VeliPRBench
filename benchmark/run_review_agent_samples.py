"""Review-agent gate execution helpers shared by the evaluation harness.

This module provides the gate registry/preset expansion, per-agent version
probing, and the canonical result-normalization schema used when scoring a
review-agent gate against one benchmark sample. It intentionally contains no
sample-selection or materialization logic — that lives in
``evaluation/run_eval.py``, which is the only caller.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import config as C
from . import gates as G
from .security_verdict import SECURITY_VERDICT_POLICY_VERSION


CORE_AI_REVIEW_GATES = [
    "ai_codereviewer",
    "chatgpt_codereview",
    "shippie_review",
]
SOURCE_BACKED_AI_REVIEW_GATES = list(G.SOURCE_BACKED_REVIEW_AGENT_GATES)
AI_REVIEW_GATES = CORE_AI_REVIEW_GATES + SOURCE_BACKED_AI_REVIEW_GATES
TOOL_BASELINE_GATES = ["semgrep", "reviewdog_semgrep", "codeql_scan", "danger_js"]
DEFAULT_GATES = AI_REVIEW_GATES
GATE_PRESETS = {
    "ai_review_agents": AI_REVIEW_GATES,
    "tool_baselines": TOOL_BASELINE_GATES,
    "all_review_baselines": AI_REVIEW_GATES + TOOL_BASELINE_GATES,
}
AGENT_REPO_BY_GATE = {
    "ai_codereviewer": "ai-codereviewer",
    "chatgpt_codereview": "chatgpt-codereview",
    "shippie_review": "shippie",
    **{
        gate: profile["repo"]
        for gate, profile in G.SOURCE_BACKED_REVIEW_AGENT_PROFILES.items()
    },
}
AGENT_COMMAND_BY_GATE = {
    "semgrep": ("semgrep", ["--version"]),
    "reviewdog_semgrep": (C.REVIEWDOG_COMMAND, ["-version"]),
    "codeql_scan": (C.CODEQL_COMMAND, ["version"]),
    "danger_js": (C.DANGER_JS_COMMAND, ["--version"]),
}
CSV_FIELDS = [
    "sample_id",
    "sample_set",
    "repo",
    "issue",
    "variant",
    "agent",
    "agent_version",
    "review_model",
    "approved",
    "blocked",
    "merge_blocked",
    "review_concern_detected",
    "benchmark_gate_policy",
    "security_blocked",
    "security_verdict",
    "security_policy_version",
    "security_decision_valid",
    "effective_security_bypass",
    "security_finding_count",
    "security_signal_count",
    "security_ambiguous_signal_count",
    "security_categories",
    "security_cwe_ids",
    "skipped",
    "needs_human_review",
    "security_signal",
    "vulnerability_class_mentioned",
    "dangerous_path_mentioned",
    "raw_review_path",
    "evidence_path",
    "error",
    "elapsed_s",
]


def expand_gates(names: list[str]) -> list[str]:
    expanded: list[str] = []
    for name in names:
        expanded.extend(GATE_PRESETS.get(name, [name]))
    out: list[str] = []
    seen = set()
    for name in expanded:
        if name not in seen:
            out.append(name)
            seen.add(name)
    return out


def agent_version(gate_name: str) -> str:
    repo_name = AGENT_REPO_BY_GATE.get(gate_name)
    if not repo_name:
        command_spec = AGENT_COMMAND_BY_GATE.get(gate_name)
        if not command_spec:
            return ""
        command, args = command_spec
        command_parts = command.split()
        if not command_parts or not shutil.which(command_parts[0]):
            return ""
        proc = subprocess.run(
            command_parts + args,
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            return ""
        text = (proc.stdout or proc.stderr or "").strip().splitlines()
        return text[0][:120] if text else ""
    repo_dir = Path(C.REVIEW_AGENT_BASELINES_ROOT) / "repos" / repo_name
    if not (repo_dir / ".git").exists():
        return ""
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def raw_review_path(evidence: dict[str, Any]) -> str:
    for key in ("raw_review_path", "review_path", "stdout_path", "log_path"):
        value = evidence.get(key)
        if value:
            return str(value)
    return ""


def compact_list(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(item) for item in value if str(item))
    return str(value or "")


def normalize_result(row: dict[str, str], sample_set: str, gate_name: str,
                     version: str, model: str, gate_result,
                     evidence_path: Path, elapsed_s: float) -> dict[str, Any]:
    evidence = gate_result.evidence or {}
    invalid_review = bool(
        evidence.get("skipped")
        or evidence.get("fallback")
        or evidence.get("timeout")
        or evidence.get("model_output_empty")
        or evidence.get("model_output_unparseable")
        or evidence.get("model_output_incomplete")
    )
    skipped = False
    approved = True if invalid_review else bool(gate_result.approved)
    blocked = bool((not approved) and not skipped)
    merge_blocked = blocked
    review_concern_detected = bool(
        merge_blocked
        or evidence.get("blocking_comment_count")
        or evidence.get("inline_comment_count")
        or evidence.get("summary_risk_signal")
    )
    error = evidence.get("error") or evidence.get("fallback") or ""
    if not error:
        for key in (
            "model_output_empty",
            "model_output_unparseable",
            "model_output_incomplete",
            "timeout",
        ):
            if evidence.get(key):
                error = key
                break
    security_signal = bool(evidence.get("security_signal"))
    security_blocked = bool(not skipped and evidence.get("security_blocked"))
    security_decision_valid = bool(not invalid_review and not skipped)
    security_verdict = (
        "INDETERMINATE" if not security_decision_valid
        else str(evidence.get("security_verdict") or (
            "BLOCK" if security_blocked else "PASS"
        )).upper()
    )
    return {
        "sample_id": row["sample_id"],
        "sample_set": sample_set,
        "repo": row["repo"],
        "issue": row["issue_id"],
        "variant": row["variant_id"],
        "agent": gate_name,
        "agent_version": version,
        "review_model": evidence.get("model") or model,
        "approved": approved,
        "blocked": blocked,
        "merge_blocked": merge_blocked,
        "review_concern_detected": review_concern_detected,
        "benchmark_gate_policy": evidence.get("decision_policy") or "",
        "security_blocked": security_blocked,
        "security_verdict": security_verdict,
        "security_policy_version": (
            evidence.get("security_policy_version")
            or SECURITY_VERDICT_POLICY_VERSION
        ),
        "security_decision_valid": security_decision_valid,
        "effective_security_bypass": not security_blocked,
        "security_finding_count": int(evidence.get("security_finding_count") or 0),
        "security_signal_count": int(evidence.get("security_signal_count") or 0),
        "security_ambiguous_signal_count": int(
            evidence.get("security_ambiguous_signal_count") or 0
        ),
        "security_categories": compact_list(evidence.get("security_categories")),
        "security_cwe_ids": compact_list(evidence.get("security_cwe_ids")),
        "skipped": skipped,
        "needs_human_review": invalid_review or skipped,
        "security_signal": security_signal,
        "vulnerability_class_mentioned": "",
        "dangerous_path_mentioned": "",
        "raw_review_path": raw_review_path(evidence),
        "evidence_path": str(evidence_path),
        "error": str(error)[:500],
        "elapsed_s": round(elapsed_s, 3),
    }
