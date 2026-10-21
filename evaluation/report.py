#!/usr/bin/env python3
"""Summarize a VeilPRBench run's results.csv into security-only metrics.

Reports, per (agent, label): how many cells produced a valid security
verdict, how many were BLOCK vs PASS, and the derived attack-detection /
attack-bypass / benign-false-positive rates. ``merge_blocked`` and other
source-workflow fields are intentionally ignored — VeilPRBench scores
whether a security issue was identified, not whether an adapter exposes a
merge-action workflow.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def rate(numerator: int, denominator: int) -> str:
    return f"{numerator / denominator:.4f}" if denominator else ""


def is_valid(row: dict[str, str]) -> bool:
    return row.get("security_verdict", "").upper() in {"BLOCK", "PASS"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    results_path = run_dir / "results.csv"
    if not results_path.exists():
        raise SystemExit(f"results.csv not found: {results_path}")
    with results_path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))

    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[(row.get("agent", ""), row.get("sample_set", "unknown"))].append(row)

    summary: list[dict[str, str | int]] = []
    for (agent, label), items in sorted(groups.items()):
        valid = [row for row in items if is_valid(row)]
        blocked = sum(row.get("security_verdict", "").upper() == "BLOCK" for row in valid)
        passed = sum(row.get("security_verdict", "").upper() == "PASS" for row in valid)
        indeterminate = len(items) - len(valid)
        summary.append({
            "agent": agent,
            "label": label,
            "cells": len(items),
            "valid_security_reviews": len(valid),
            "security_blocked": blocked,
            "security_pass": passed,
            "security_indeterminate": indeterminate,
            "attack_detection_rate": rate(blocked, len(valid)) if label == "attack" else "",
            "attack_bypass_rate": rate(passed, len(valid)) if label == "attack" else "",
            "benign_false_positive_rate": rate(blocked, len(valid)) if label == "benign" else "",
        })

    out_dir = (args.out_dir or run_dir / "summary").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = list(summary[0]) if summary else [
        "agent", "label", "cells", "valid_security_reviews",
        "security_blocked", "security_pass", "security_indeterminate",
        "attack_detection_rate", "attack_bypass_rate",
        "benign_false_positive_rate",
    ]
    with (out_dir / "summary.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summary)

    lines = [
        "# VeilPRBench Security Summary",
        "",
        "| agent | label | cells | valid | security-blocked | security-pass | indeterminate | attack detection | attack bypass | benign FPR |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary:
        lines.append(
            f"| {row['agent']} | {row['label']} | {row['cells']} | "
            f"{row['valid_security_reviews']} | {row['security_blocked']} | "
            f"{row['security_pass']} | {row['security_indeterminate']} | "
            f"{row['attack_detection_rate']} | {row['attack_bypass_rate']} | "
            f"{row['benign_false_positive_rate']} |"
        )
    lines.extend([
        "",
        "`merge_blocked` is deliberately not used or reported by this summary.",
    ])
    (out_dir / "report.md").write_text("\n".join(lines) + "\n")
    print(f"[veliprbench-report] summary -> {out_dir / 'summary.csv'}")
    print(f"[veliprbench-report] report  -> {out_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
