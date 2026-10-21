#!/usr/bin/env python3
"""Run review-agent gates against the VeilPRBench corpus (data/manifest.csv).

For each selected sample this script: clones the target project at its
pinned baseline tag (cached under repos/<repo>/work/), materializes the
sample's frozen diff into an isolated worktree + commit, then runs each
requested gate's review() against that commit's diff, PR description, and
the plugin's live Issue record. Results are checkpointed incrementally to
results.jsonl/results.csv so a run can be resumed with --resume.

See evaluation/report.py to turn a run's results.csv into per-agent
attack-detection / benign-false-positive metrics.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import fcntl
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmark import config as C  # noqa: E402
from benchmark import gates as G  # noqa: E402
from benchmark import harness as H  # noqa: E402
from benchmark.core import get_repo  # noqa: E402
from benchmark import run_review_agent_samples as canonical  # noqa: E402

OUTPUT_FIELDS = canonical.CSV_FIELDS


def acquire_run_lock(out_dir: Path):
    """Prevent concurrent writers from corrupting a resumable run directory."""
    lock_path = out_dir / ".run.lock"
    handle = lock_path.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise SystemExit(
            f"run directory is already active: {out_dir}; choose another out-dir or wait"
        )
    handle.seek(0)
    handle.truncate()
    handle.write(f"pid={os.getpid()}\n")
    handle.flush()
    return handle


def load_manifest(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def select_rows(rows: list[dict[str, str]], *, labels: list[str],
                repos: list[str], sample_ids: list[str],
                limit: int | None) -> list[dict[str, str]]:
    if labels:
        wanted = set(labels)
        rows = [row for row in rows if row["label"] in wanted]
    if repos:
        wanted = set(repos)
        rows = [row for row in rows if row["repo"] in wanted]
    if sample_ids:
        wanted = set(sample_ids)
        rows = [row for row in rows if row["sample_id"] in wanted]
        missing = wanted - {row["sample_id"] for row in rows}
        if missing:
            raise SystemExit(f"sample_id(s) not found: {sorted(missing)}")
    if limit is not None:
        rows = rows[:limit]
    if not rows:
        raise SystemExit("no samples selected")
    return rows


_BASELINE_PLUGINS: dict[str, Any] = {}
_BASELINE_PLUGINS_LOCK = threading.Lock()


def baseline_plugin(repo_name: str):
    """Clone/reset a project's baseline checkout once per process, then reuse it."""
    with _BASELINE_PLUGINS_LOCK:
        plugin = _BASELINE_PLUGINS.get(repo_name)
        if plugin is None:
            plugin = get_repo(repo_name)
            plugin.clone_or_reset()
            _BASELINE_PLUGINS[repo_name] = plugin
        return plugin


def materialize_sample(row: dict[str, str], sample_dir: Path,
                       data_dir: Path) -> dict[str, Any]:
    """Apply one frozen sample diff to an isolated local worktree and commit it."""
    source_plugin = baseline_plugin(row["repo"])
    source_repo = Path(source_plugin.repo_root)
    cfg = source_plugin.config()

    diff_path = data_dir / row["diff_path"]
    pr_path = data_dir / row["pr_description_path"]
    for required_path in (source_repo / ".git", diff_path, pr_path):
        if not required_path.exists():
            raise FileNotFoundError(str(required_path))

    worktree = sample_dir / "worktree"
    if worktree.exists():
        shutil.rmtree(worktree)
    sample_dir.mkdir(parents=True, exist_ok=True)
    H.run(["git", "clone", "--shared", str(source_repo), str(worktree)])
    H.git(worktree, ["config", "user.email", "veliprbench@example.local"])
    H.git(worktree, ["config", "user.name", "VeilPRBench"])
    H.git(worktree, ["checkout", "-f", cfg.tag])
    H.git(worktree, ["branch", "-f", cfg.base_branch, cfg.tag])
    H.git(worktree, ["checkout", cfg.base_branch])
    H.git(worktree, ["reset", "--hard", cfg.tag])
    H.git(worktree, ["apply", "--3way", "--whitespace=nowarn", str(diff_path)])
    H.git(worktree, ["add", "-A"])
    staged_diff = H.git(worktree, ["diff", "--cached"], capture=True).stdout
    if not staged_diff.strip():
        raise RuntimeError("materialized sample has empty staged diff")

    branch = cfg.fix_branch_for(row["issue_id"])
    H.git(worktree, ["checkout", "-b", branch])
    H.git(worktree, ["commit", "-m", f"Fix #{row['issue_id']}"])
    committed_diff = H.git(
        worktree, ["diff", f"{cfg.base_branch}...HEAD"], capture=True
    ).stdout
    (sample_dir / "committed.diff").write_text(committed_diff)

    return {
        "worktree": worktree,
        "committed_diff": committed_diff,
        "pr_md": pr_path.read_text(),
    }


def failure_row(row: dict[str, str], error: Exception) -> dict[str, Any]:
    """Emit an explicit indeterminate result for materialization failures."""
    result = {field: "" for field in OUTPUT_FIELDS}
    result.update({
        "sample_id": row.get("sample_id", ""),
        "sample_set": row.get("label", ""),
        "repo": row.get("repo", ""),
        "issue": row.get("issue_id", ""),
        "variant": row.get("variant_id", ""),
        "agent": "materialize",
        "approved": True,
        "blocked": False,
        "merge_blocked": False,
        "review_concern_detected": False,
        "security_blocked": False,
        "security_verdict": "INDETERMINATE",
        "security_decision_valid": False,
        "effective_security_bypass": False,
        "skipped": False,
        "needs_human_review": True,
        "security_signal": False,
        "error": f"materialize_failed:{error}",
        "elapsed_s": 0,
    })
    return result


def execute_sample(
    row: dict[str, str],
    remaining_gates: list[str],
    *,
    out_dir: Path,
    data_dir: Path,
    keep_worktrees: bool,
) -> list[tuple[dict[str, Any], dict[str, Any] | None, str]]:
    """Materialize and review one sample without mutating shared checkpoints."""
    sample_dir = out_dir / "samples" / row["sample_id"]
    worktree = sample_dir / "worktree"
    try:
        manifest = materialize_sample(row, sample_dir, data_dir)
    except Exception as exc:  # noqa: BLE001
        if not keep_worktrees and worktree.exists():
            shutil.rmtree(worktree)
        return [
            (failure_row(row, exc), None, f"materialize -> INDETERMINATE {exc}")
        ]

    diff_text = manifest["committed_diff"]
    pr_md = manifest["pr_md"]
    events: list[tuple[dict[str, Any], dict[str, Any] | None, str]] = []
    try:
        for gate_name in remaining_gates:
            cell_dir = out_dir / "cells" / f"{row['sample_id']}__{gate_name}"
            artifacts_dir = cell_dir / "artifacts"
            plugin = get_repo(row["repo"], repo_root=worktree,
                              artifacts_dir=artifacts_dir)
            issue = plugin.get_issue(row["issue_id"])
            gate = G.build_gate(gate_name, plugin)
            version = canonical.agent_version(gate_name)
            t0 = time.time()
            try:
                gate_result = gate.review(diff_text, pr_md, issue)
                evidence = {
                    "gate": gate.name,
                    "approved": gate_result.approved,
                    "reason": gate_result.reason,
                    "evidence": gate_result.evidence,
                }
            except Exception as exc:  # noqa: BLE001
                gate_result = type("GateResult", (), {
                    "approved": True,
                    "reason": f"{gate_name}: runner exception",
                    "evidence": {
                        "skipped": True,
                        "fallback": "runner_exception",
                        "error": str(exc),
                    },
                })()
                evidence = {
                    "gate": gate_name,
                    "approved": True,
                    "reason": gate_result.reason,
                    "evidence": gate_result.evidence,
                }
            elapsed = time.time() - t0
            cell_dir.mkdir(parents=True, exist_ok=True)
            evidence_path = cell_dir / "gate_result.json"
            evidence_path.write_text(json.dumps(evidence, indent=2))
            result = canonical.normalize_result(
                row, row["label"], gate_name, version,
                C.REVIEW_AGENT_MODEL, gate_result, evidence_path, elapsed,
            )
            events.append((result, evidence, gate_result.reason))
    finally:
        if not keep_worktrees and worktree.exists():
            shutil.rmtree(worktree)
    return events


def write_checkpoint(out_dir: Path, rows: list[dict[str, Any]]) -> None:
    with (out_dir / "results.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_existing_results(path: Path) -> list[dict[str, Any]]:
    """Read append-only checkpoints, ignoring a truncated final JSONL line."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open() as fh:
        for line in fh:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            result = record.get("result")
            if isinstance(result, dict):
                rows.append(result)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path,
                        default=PROJECT_ROOT / "data" / "manifest.csv")
    parser.add_argument("--data-dir", type=Path, default=None,
                        help="Base dir for diff/PR paths in the manifest "
                             "(default: --manifest's parent directory).")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--gates", nargs="+", default=canonical.DEFAULT_GATES,
                        help="Gate names or presets (ai_review_agents, "
                             "tool_baselines, all_review_baselines).")
    parser.add_argument("--label", action="append", default=[], dest="labels",
                        choices=["attack", "benign"])
    parser.add_argument("--repo", action="append", default=[], dest="repos")
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=1,
                        help="Independent sample workers; each sample retains "
                             "an isolated worktree and cell artifacts.")
    parser.add_argument("--keep-worktrees", action="store_true")
    parser.add_argument("--resume", action="store_true",
                        help="Append only missing sample/gate cells to an "
                             "existing run.")
    args = parser.parse_args()

    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")

    data_dir = (args.data_dir or args.manifest.resolve().parent).resolve()
    gates = canonical.expand_gates(args.gates)
    unknown = [name for name in gates if name not in G.GATE_NAMES]
    if unknown:
        raise SystemExit(f"unknown gate(s): {unknown}")

    rows = select_rows(
        load_manifest(args.manifest),
        labels=args.labels, repos=args.repos,
        sample_ids=args.sample_id, limit=args.limit,
    )

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    run_lock = acquire_run_lock(out_dir)  # noqa: F841 (held for process lifetime)
    jsonl_path = out_dir / "results.jsonl"
    if args.resume:
        normalized_rows = load_existing_results(jsonl_path)
    else:
        if jsonl_path.exists():
            raise SystemExit(
                f"run directory already contains results: {out_dir}; use --resume"
            )
        normalized_rows = []

    completed_cells = {
        (str(result.get("sample_id", "")), str(result.get("agent", "")))
        for result in normalized_rows
        if result.get("agent") in gates
    }
    prior_materialization_failures = {
        str(result.get("sample_id", ""))
        for result in normalized_rows
        if result.get("agent") == "materialize"
    }
    jsonl_mode = "a" if args.resume else "w"
    pending: list[tuple[dict[str, str], list[str]]] = []
    for row in rows:
        sample_id = row["sample_id"]
        remaining_gates = [
            gate_name for gate_name in gates
            if (sample_id, gate_name) not in completed_cells
        ]
        if not remaining_gates:
            print(f"[veliprbench] {sample_id} -> already complete")
            continue
        if sample_id in prior_materialization_failures:
            print(f"[veliprbench] {sample_id} -> prior materialize failure; skipped")
            continue
        pending.append((row, remaining_gates))

    with jsonl_path.open(jsonl_mode) as jsonl:
        def record_events(
            events: list[tuple[dict[str, Any], dict[str, Any] | None, str]],
        ) -> None:
            for result, evidence, reason in events:
                payload: dict[str, Any] = {"result": result}
                if evidence is not None:
                    payload["evidence"] = evidence
                jsonl.write(json.dumps(payload) + "\n")
                jsonl.flush()
                normalized_rows.append(result)
                sample_id = str(result.get("sample_id", ""))
                agent = str(result.get("agent", ""))
                if agent in gates:
                    completed_cells.add((sample_id, agent))
                print(
                    f"[veliprbench] {sample_id} {agent} -> "
                    f"{result.get('security_verdict', 'INDETERMINATE')} ({reason})"
                )
            write_checkpoint(out_dir, normalized_rows)

        if args.workers == 1:
            for row, remaining_gates in pending:
                record_events(execute_sample(
                    row, remaining_gates, out_dir=out_dir, data_dir=data_dir,
                    keep_worktrees=args.keep_worktrees,
                ))
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.workers,
                thread_name_prefix="veliprbench-sample",
            ) as executor:
                futures = {
                    executor.submit(
                        execute_sample, row, remaining_gates,
                        out_dir=out_dir, data_dir=data_dir,
                        keep_worktrees=args.keep_worktrees,
                    ): row
                    for row, remaining_gates in pending
                }
                for future in concurrent.futures.as_completed(futures):
                    row = futures[future]
                    try:
                        events = future.result()
                    except Exception as exc:  # noqa: BLE001
                        events = [
                            (failure_row(row, exc), None,
                             f"runner -> INDETERMINATE {exc}")
                        ]
                    record_events(events)

    write_checkpoint(out_dir, normalized_rows)
    print(f"[veliprbench] results -> {out_dir / 'results.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
