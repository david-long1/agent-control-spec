# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A second control that is not ACS, and could not be.

The ACS runtime is stateless and deterministic by specification: the
same manifest and the same context always produce the same verdict. A
cumulative spend cap is the opposite: its answer depends on what this
session already spent. That state belongs to the host, and a host
control is how it enters the decision.

It matters for composition that this control is *mandatory*: the whole
point of a spend cap is that nothing gets past it. Under
``sequential/first_deny`` with ``on_approval: stop``, a control
registered after one that escalates is skipped once an approver lifts
the deny. Under ``sequential/run_all`` every control runs before
anything is aggregated or escalated.

The control reads ``context["target"]``, not the arguments the host
built. In the sequential profiles a predecessor's transform has already
folded into the context by the time this runs, so reading ``target``
means the cap is applied to the amount that will actually be spent.
"""

from __future__ import annotations

import math
import threading
from collections.abc import Mapping
from typing import Any

from agent_hooks import Verdict


class RefundBudgetControl:
    """Cumulative refund cap for one logical session.

    One instance is the cap. Child tasks, worker threads and background
    work that belong to the same logical session must share this
    instance, or each gets its own full budget and the cap means
    nothing. The lock is here for that reason.
    """

    def __init__(self, cap: float, *, name: str = "budget") -> None:
        self.cap = cap
        self.name = name
        self.committed = 0.0
        self.evaluated: list[float] = []
        self._lock = threading.Lock()

    def remaining(self) -> float:
        with self._lock:
            return self.cap - self.committed

    def intercept(self, context: Mapping[str, Any]) -> Verdict:
        if context["interception_point"] != "pre_tool_call":
            return Verdict.allow()
        if (context.get("tool_call") or {}).get("name") != "issue_refund":
            return Verdict.allow()

        raw = (context.get("target") or {}).get("amount")
        try:
            amount = float(raw)
        except (TypeError, ValueError):
            amount = math.nan

        # A cap that accepts a negative or non-finite amount is not a
        # cap: one negative "refund" would hand back capacity for real
        # ones. Reject the value rather than arithmetic on it.
        if not math.isfinite(amount) or amount <= 0:
            return Verdict.deny(
                reason="refund_amount_invalid",
                message="A refund amount must be a finite number greater than zero.",
            )

        with self._lock:
            committed = self.committed
            self.evaluated.append(amount)
        if committed + amount > self.cap:
            return Verdict.deny(
                reason="refund_budget_exceeded",
                message=(
                    f"This session has committed {committed:.2f} of a "
                    f"{self.cap:.2f} refund budget; {amount:.2f} more would exceed it."
                ),
            )
        return Verdict.allow()

    def commit(self, amount: float) -> None:
        """Called by the host only after the refund actually happened."""
        if not math.isfinite(amount) or amount <= 0:
            raise ValueError(f"refusing to commit a non-positive refund: {amount!r}")
        with self._lock:
            self.committed += amount
