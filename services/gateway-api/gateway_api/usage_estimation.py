from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from statistics import fmean
from typing import Iterable

FINAL_RESPONSE_ESTIMATOR_PROFILE_ID = "gateway-visible-final-response-v1"
FINAL_RESPONSE_ESTIMATOR_VERSION = "1.0.0"
FINAL_RESPONSE_ESTIMATOR_CONFIDENCE = 0.72
FINAL_RESPONSE_ESTIMATOR_EVIDENCE_REF = (
    "urn:klab:gateway:lup-estimator:gateway-visible-final-response-v1:1.0.0"
)
FINAL_RESPONSE_EXCLUDED_INPUTS = (
    "system_context",
    "hidden_reasoning",
    "provider_transformations",
    "cached_context",
    "unknown_internal_calls",
)


@dataclass(frozen=True, slots=True)
class FinalResponseCountMetrics:
    visible_character_count: int
    visible_utf8_byte_count: int
    visible_word_count: int


@dataclass(frozen=True, slots=True)
class CalibrationSample:
    visible_character_count: int
    visible_utf8_byte_count: int
    visible_word_count: int
    exact_output_tokens: int


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    profile_id: str
    estimator_version: str
    sample_count: int
    bound_coverage: float
    mean_absolute_percentage_error: float
    maximum_absolute_percentage_error: float

    def as_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "estimator_version": self.estimator_version,
            "sample_count": self.sample_count,
            "bound_coverage": self.bound_coverage,
            "mean_absolute_percentage_error": self.mean_absolute_percentage_error,
            "maximum_absolute_percentage_error": self.maximum_absolute_percentage_error,
        }


def _central_estimate(metrics: FinalResponseCountMetrics) -> int:
    if metrics.visible_character_count == 0:
        return 0
    character_estimate = metrics.visible_character_count / 4.0
    byte_estimate = metrics.visible_utf8_byte_count / 4.5
    word_estimate = metrics.visible_word_count * 1.25
    return max(1, math.ceil(max(character_estimate, byte_estimate, word_estimate)))


def _bounds(estimated_tokens: int) -> tuple[int, int]:
    if estimated_tokens == 0:
        return 0, 0
    lower = max(0, math.floor(estimated_tokens * 0.60))
    upper = max(estimated_tokens, math.ceil(estimated_tokens * 1.75 + 4))
    return lower, upper


def estimate_visible_final_response(
    *,
    model: dict[str, object],
    metrics: FinalResponseCountMetrics,
) -> dict[str, object]:
    estimated_tokens = _central_estimate(metrics)
    lower_bound, upper_bound = _bounds(estimated_tokens)
    evidence_payload = {
        "profile": FINAL_RESPONSE_ESTIMATOR_PROFILE_ID,
        "version": FINAL_RESPONSE_ESTIMATOR_VERSION,
        "visible_character_count": metrics.visible_character_count,
        "visible_utf8_byte_count": metrics.visible_utf8_byte_count,
        "visible_word_count": metrics.visible_word_count,
    }
    evidence_digest = hashlib.sha256(
        json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "model": dict(model),
        "tokens": {"output_tokens": estimated_tokens},
        "measurement_kind": "heuristic_estimate",
        "covered_categories": ["output"],
        "estimation": {
            "estimator_profile_id": FINAL_RESPONSE_ESTIMATOR_PROFILE_ID,
            "estimator_version": FINAL_RESPONSE_ESTIMATOR_VERSION,
            "confidence": FINAL_RESPONSE_ESTIMATOR_CONFIDENCE,
            "lower_bound_tokens": lower_bound,
            "upper_bound_tokens": upper_bound,
            "covered_inputs": ["final_response"],
            "excluded_inputs": list(FINAL_RESPONSE_EXCLUDED_INPUTS),
            "evidence_ref": f"{FINAL_RESPONSE_ESTIMATOR_EVIDENCE_REF}#{evidence_digest}",
        },
    }


def evaluate_calibration(samples: Iterable[CalibrationSample]) -> CalibrationReport:
    values = tuple(samples)
    if not values:
        raise ValueError("at least one calibration sample is required")
    covered = 0
    percentage_errors: list[float] = []
    for sample in values:
        metrics = FinalResponseCountMetrics(
            visible_character_count=sample.visible_character_count,
            visible_utf8_byte_count=sample.visible_utf8_byte_count,
            visible_word_count=sample.visible_word_count,
        )
        estimate = _central_estimate(metrics)
        lower, upper = _bounds(estimate)
        if lower <= sample.exact_output_tokens <= upper:
            covered += 1
        denominator = max(1, sample.exact_output_tokens)
        percentage_errors.append(abs(estimate - sample.exact_output_tokens) / denominator)
    return CalibrationReport(
        profile_id=FINAL_RESPONSE_ESTIMATOR_PROFILE_ID,
        estimator_version=FINAL_RESPONSE_ESTIMATOR_VERSION,
        sample_count=len(values),
        bound_coverage=covered / len(values),
        mean_absolute_percentage_error=fmean(percentage_errors),
        maximum_absolute_percentage_error=max(percentage_errors),
    )
