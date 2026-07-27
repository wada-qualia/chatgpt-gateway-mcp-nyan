from __future__ import annotations

import argparse
import json
from pathlib import Path

from gateway_api.mcp_evaluation import load_evaluation_contract, run_evaluation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="configs/mcp-federation/phase-9-evaluation.json",
    )
    parser.add_argument(
        "--output",
        default="artifacts/evaluation/phase-9-evaluation-report.json",
    )
    args = parser.parse_args()

    contract = load_evaluation_contract(args.config)
    report = run_evaluation(contract)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary = {
        "status": report["status"],
        "contract_sha256": report["contract_sha256"],
        "fixture_counts": report["fixture_counts"],
        "global_metrics": report["global_metrics"],
        "profiles": {
            profile: payload["metrics"]
            for profile, payload in report["profiles"].items()
        },
        "violations": report["violations"],
        "output": str(output),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
