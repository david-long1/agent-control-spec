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

from collections.abc import Mapping
from typing import Any

from agent_hooks import Verdict


class RefundBudgetControl:
    """Per-session cumulative refund cap."""

    def __init__(self, cap: float, *, name: str = "budget") -> None:
        self.cap = cap
        self.name = name
        self.committed = 0.0
        self.evaluated: list[float] = []

    def remaining(self) -> float:
        return self.cap - self.committed

    def intercept(self, context: Mapping[str, Any]) -> Verdict:
        if context["interception_point"] != "pre_tool_call":
            return Verdict.allow()
        if (context.get("tool_call") or {}).get("name") != "issue_refund":
            return Verdict.allow()

        amount = float((context.get("target") or {}).get("amount", 0.0))
        self.evaluated.append(amount)
        if self.committed + amount > self.cap:
            return Verdict.deny(
                reason="refund_budget_exceeded",
                message=(
                    f"This session has committed {self.committed:.2f} of a "
                    f"{self.cap:.2f} refund budget; {amount:.2f} more would exceed it."
                ),
            )
        return Verdict.allow()

    def commit(self, amount: float) -> None:
        """Called by the host only after the refund actually happened."""
        self.committed += amount
