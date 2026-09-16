# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deterministic stand-ins for the classifiers the manifest declares.

An annotator dispatcher is where the host's I/O lives: the model call,
the content-safety request, the cache and its timeout. The runtime calls
it synchronously and reads nothing else about the outside world. Keeping
these stubs local and deterministic is what makes the example's verdicts
reproducible and free to run.

A dispatcher that raises is not a silent no-op: the runtime normalizes
the failure into a fail-closed ``deny`` carrying
``runtime_error:annotation_failed``.
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from typing import Any

_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "developer message",
    "disregard your instructions",
)
_FRAUD_MARKERS = ("stolen", "chargeback abuse", "card testing")
_PII_PATTERNS = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b\d{3}[-.]\d{3}[-.]\d{4}\b"),
)


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return " ".join(
            str(v) for v in value.values() if isinstance(v, (str, int, float))
        )
    return str(value)


class LocalAnnotators:
    """Host annotator dispatcher.

    ``latency_s`` simulates a slow classifier so the example can show
    what a host's evaluation-timeout budget is actually protecting
    against. ``fail`` simulates a classifier that is down.
    """

    def __init__(self, *, latency_s: float = 0.0, fail: bool = False) -> None:
        self.latency_s = latency_s
        self.fail = fail
        self.calls: list[str] = []

    def dispatch(
        self,
        annotator_name: str,
        annotator_config: Mapping[str, Any],
        preliminary_policy_input: Mapping[str, Any],
    ) -> Any:
        self.calls.append(annotator_name)
        if self.fail:
            raise RuntimeError("content classifier unreachable")
        if self.latency_s:
            time.sleep(self.latency_s)

        target = preliminary_policy_input["policy_target"]["value"]

        if annotator_name == "injection_risk":
            text = _text(target).lower()
            label = (
                "prompt_injection"
                if any(m in text for m in _INJECTION_MARKERS)
                else "benign"
            )
            return {"label": label}

        if annotator_name == "refund_risk":
            reason = (
                str(target.get("reason", "")).lower()
                if isinstance(target, Mapping)
                else ""
            )
            label = (
                "fraudulent" if any(m in reason for m in _FRAUD_MARKERS) else "ordinary"
            )
            return {"label": label}

        if annotator_name == "pii_scan":
            text = _text(target)
            redacted = text
            for pattern in _PII_PATTERNS:
                redacted = pattern.sub("[redacted]", redacted)
            label = "pii_present" if redacted != text else "clear"
            return {"label": label, "redacted": redacted}

        raise ValueError(f"unknown annotator: {annotator_name}")
