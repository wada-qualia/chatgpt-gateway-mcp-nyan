#!/usr/bin/env python3
"""Run the canonical MCP Federation Phase 7 acceptance matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from datetime import UTC, datetime

import yaml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default="configs/mcp-federation/phase-7-acceptance.yaml",
    )
    parser.add_argument("--evidence", help="Optional JSON evidence output path")
    parser.add_argument("--collect-only", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest_path = (root / args.manifest).resolve()
    manifest = yaml.safe_load(manifest_path.read_text())
    nodeids: list[str] = []
    for scenario in manifest["scenarios"]:
        for nodeid in scenario["nodeids"]:
            if nodeid not in nodeids:
                nodeids.append(nodeid)

    command = [sys.executable, "-m", "pytest", "-q", *nodeids]
    started = datetime.now(UTC)
    if args.collect_only:
        print("\n".join(nodeids))
        return 0
    completed = subprocess.run(command, cwd=root, check=False)
    finished = datetime.now(UTC)
    evidence = {
        "schema_version": 1,
        "task": manifest["task"],
        "manifest": str(manifest_path.relative_to(root)),
        "nodeid_count": len(nodeids),
        "scenario_count": len(manifest["scenarios"]),
        "required_levels": manifest["required_levels"],
        "legacy_surface_sha256": manifest["legacy_surface_sha256"],
        "started_at": started.isoformat(),
        "completed_at": finished.isoformat(),
        "exit_code": completed.returncode,
        "status": "passed" if completed.returncode == 0 else "failed",
    }
    if args.evidence:
        evidence_path = (root / args.evidence).resolve()
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, sort_keys=True))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
