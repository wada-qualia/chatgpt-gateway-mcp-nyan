#!/usr/bin/env python3
"""Validate and run the MCP Federation Phase 8 protocol matrix."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess
import sys

import yaml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default="configs/mcp-federation/phase-8-protocol-capabilities.yaml",
    )
    parser.add_argument("--evidence")
    parser.add_argument("--collect-only", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest_path = (root / args.manifest).resolve()
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    qualification = manifest["qualification"]
    nodeids: list[str] = []
    for scenario in qualification["scenarios"]:
        for nodeid in scenario["nodeids"]:
            if nodeid not in nodeids:
                nodeids.append(nodeid)

    if args.collect_only:
        print("\n".join(nodeids))
        return 0

    started = datetime.now(UTC)
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *nodeids],
        cwd=root,
        check=False,
    )
    finished = datetime.now(UTC)
    evidence = {
        "schema_version": 1,
        "task": manifest["task"],
        "manifest": str(manifest_path.relative_to(root)),
        "stable_protocol_version": manifest["specification"][
            "stable_protocol_version"
        ],
        "accepted_protocol_versions": manifest["specification"][
            "accepted_protocol_versions"
        ],
        "scenario_count": len(qualification["scenarios"]),
        "nodeid_count": len(nodeids),
        "required_levels": qualification["required_levels"],
        "started_at": started.isoformat(),
        "completed_at": finished.isoformat(),
        "exit_code": completed.returncode,
        "status": "passed" if completed.returncode == 0 else "failed",
    }
    if args.evidence:
        evidence_path = (root / args.evidence).resolve()
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(evidence, sort_keys=True))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
