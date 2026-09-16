# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Inert local tools. Nothing here reaches the network or a paid service.

``LEDGER`` exists so a test can assert what the agent *actually did*,
which is the only way to show that a deny prevented an effect rather
than merely recording a disapproving verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_ORDERS = {
    "A-1001": {"total": 40.0, "customer": "dana@example.net", "status": "delivered"},
    "A-1002": {"total": 250.0, "customer": "sam@example.net", "status": "delivered"},
    "A-1003": {"total": 150.0, "customer": "lee@example.net", "status": "delivered"},
}


@dataclass
class Ledger:
    """Every refund this process actually issued."""

    entries: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> float:
        return sum(e["amount"] for e in self.entries)


class RefundTools:
    def __init__(self) -> None:
        self.ledger = Ledger()

    def lookup_order(self, *, order_id: str) -> dict[str, Any]:
        order = _ORDERS.get(order_id)
        if order is None:
            raise KeyError(order_id)
        return {"order_id": order_id, **order}

    def issue_refund(
        self, *, order_id: str, amount: float, reason: str
    ) -> dict[str, Any]:
        entry = {"order_id": order_id, "amount": amount, "reason": reason}
        self.ledger.entries.append(entry)
        return {"refunded": amount, "order_id": order_id}

    def call(self, name: str, args: dict[str, Any]) -> Any:
        return getattr(self, name)(**args)
