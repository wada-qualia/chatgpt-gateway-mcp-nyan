#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from gateway_api.usage_estimation import CalibrationSample, evaluate_calibration


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the versioned LUP final-response estimator using numeric-only samples."
    )
    parser.add_argument(
        "samples",
        nargs="?",
        type=Path,
        default=Path("configs/lup/final-response-calibration-v1.json"),
    )
    parser.add_argument("--minimum-coverage", type=float, default=0.95)
    args = parser.parse_args()
    payload = json.loads(args.samples.read_text(encoding="utf-8"))
    samples = [CalibrationSample(**item) for item in payload]
    report = evaluate_calibration(samples)
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0 if report.bound_coverage >= args.minimum_coverage else 1


if __name__ == "__main__":
    raise SystemExit(main())
