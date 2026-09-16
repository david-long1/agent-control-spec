# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Composition: what happens when ACS is not the only control.

The composition guide's claims, asserted. The one that matters most is
``test_first_deny_with_stop_skips_a_later_mandatory_control``: it shows
a refund going through that the budget control would have denied,
because a profile knob ended the emission before that control ran.
"""

from __future__ import annotations

import pytest
from agent_hooks import (
    ApprovalOutcome,
    ApprovalResolution,
    CompositionConfig,
    Decision,
    OnApproval,
    Verdict,
)
from app.host import RefundSession

ESCALATING_REFUND = {"order_id": "A-1002", "amount": 250.0, "reason": "late delivery"}


class RecordingApprover:
    """Stands in for a human queue. Records what it was asked."""

    def __init__(self, outcome: ApprovalOutcome = ApprovalOutcome.APPROVE) -> None:
        self.outcome = outcome
        self.requests: list[str] = []

    def resolve(self, request) -> ApprovalResolution:
        self.requests.append(request.interception_point.value)
        verdict = (
            Verdict.allow()
            if self.outcome is ApprovalOutcome.APPROVE
            else Verdict.deny(reason="rejected_by_reviewer")
        )
        # The echo rule: the resolution must return the request's
        # identity byte for byte.
        return ApprovalResolution(
            outcome=self.outcome,
            context_identity=request.context_identity,
            verdict=verdict,
        )


@pytest.mark.asyncio
async def test_run_all_runs_every_control_before_aggregating(policy):
    approver = RecordingApprover()
    session = RefundSession(
        policy,
        session_id="run-all",
        budget_cap=1000.0,
        composition=CompositionConfig.run_all(),
        resolver=approver,
    )

    guarded = await session.call_tool("c1", "issue_refund", ESCALATING_REFUND)

    assert guarded.proceeded
    assert guarded.record.resolved_by == "approval"
    # The mandatory control was evaluated even though ACS escalated.
    assert session.budget.evaluated == [250.0]
    assert [v.name for v in guarded.record.verdicts] == ["acs", "budget"]


@pytest.mark.asyncio
async def test_run_all_lets_a_mandatory_deny_win_over_an_escalation(policy):
    """Approval eligibility: the seam is consulted only when the
    aggregate winner is liftable. A plain deny from any control is not."""
    approver = RecordingApprover()
    session = RefundSession(
        policy,
        session_id="run-all-budget",
        budget_cap=50.0,
        composition=CompositionConfig.run_all(),
        resolver=approver,
    )

    guarded = await session.call_tool("c1", "issue_refund", ESCALATING_REFUND)

    assert not guarded.proceeded
    assert guarded.reason == "refund_budget_exceeded"
    assert approver.requests == []
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_first_deny_with_stop_skips_a_later_mandatory_control(policy):
    """The configuration to be careful with.

    ACS escalates, the approver lifts the deny, ``on_approval: stop``
    ends the emission -- and the budget control, which would have denied
    this refund, never runs. The money moves.
    """
    approver = RecordingApprover()
    session = RefundSession(
        policy,
        session_id="first-deny-stop",
        budget_cap=50.0,
        composition=CompositionConfig.first_deny(OnApproval.STOP),
        resolver=approver,
    )

    guarded = await session.call_tool("c1", "issue_refund", ESCALATING_REFUND)

    assert guarded.proceeded
    assert session.budget.evaluated == []
    assert session.tools.ledger.total == 250.0
    # The record says so rather than hiding it.
    assert guarded.record.fold_truncated is True


@pytest.mark.asyncio
async def test_first_deny_with_resume_continues_the_fold(policy):
    approver = RecordingApprover()
    session = RefundSession(
        policy,
        session_id="first-deny-resume",
        budget_cap=50.0,
        composition=CompositionConfig.first_deny(OnApproval.RESUME),
        resolver=approver,
    )

    guarded = await session.call_tool("c1", "issue_refund", ESCALATING_REFUND)

    assert session.budget.evaluated == [250.0]
    assert not guarded.proceeded
    assert guarded.reason == "refund_budget_exceeded"
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_a_rejected_escalation_stays_denied(policy):
    approver = RecordingApprover(ApprovalOutcome.REJECT)
    session = RefundSession(
        policy,
        session_id="rejected",
        composition=CompositionConfig.run_all(),
        resolver=approver,
    )

    guarded = await session.call_tool("c1", "issue_refund", ESCALATING_REFUND)

    assert not guarded.proceeded
    assert guarded.record.resolved_by == "rejection"
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_without_a_resolver_a_liftable_deny_is_just_a_deny(policy):
    session = RefundSession(
        policy,
        session_id="no-resolver",
        composition=CompositionConfig.run_all(),
    )

    guarded = await session.call_tool("c1", "issue_refund", ESCALATING_REFUND)

    assert not guarded.proceeded
    assert guarded.record.verdict.is_liftable
    assert guarded.record.resolved_by is None
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_sequential_profiles_fold_a_transform_through_to_later_controls(policy):
    """The budget control is charged against the capped amount."""
    session = RefundSession(
        policy,
        session_id="fold",
        budget_cap=120.0,
        composition=CompositionConfig.run_all(),
    )

    guarded = await session.call_tool(
        "c1", "issue_refund", {"order_id": "A-1003", "amount": 150.0, "reason": "late"}
    )

    assert guarded.proceeded
    assert guarded.record.verdict.decision is Decision.TRANSFORM
    assert session.budget.evaluated == [100.0]
    assert session.tools.ledger.total == 100


@pytest.mark.asyncio
async def test_parallel_profiles_isolate_the_snapshot_instead(policy):
    """Same controls, same request, opposite outcome.

    ``parallel/strictest`` gives every control the same untransformed
    snapshot, so the budget control sees the requested 150 rather than
    the capped 100, and denies.
    """
    session = RefundSession(
        policy,
        session_id="isolated",
        budget_cap=120.0,
        composition=CompositionConfig.strictest(),
    )

    guarded = await session.call_tool(
        "c1", "issue_refund", {"order_id": "A-1003", "amount": 150.0, "reason": "late"}
    )

    assert not guarded.proceeded
    assert session.budget.evaluated == [150.0]
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_the_profile_in_effect_is_on_every_record(policy):
    session = RefundSession(
        policy,
        session_id="recorded",
        composition=CompositionConfig.first_deny(OnApproval.RESUME),
    )

    guarded = await session.call_tool(
        "c1",
        "issue_refund",
        {"order_id": "A-1001", "amount": 40.0, "reason": "damaged"},
    )

    assert guarded.record.composition.to_wire() == {
        "profile": "sequential/first_deny",
        "on_approval": "resume",
    }
    assert guarded.record.interceptors_registered == 2
