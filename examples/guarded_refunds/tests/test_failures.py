# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Failures. None of them turn into an allow.

A guide that only shows the happy path teaches people to write
``except Exception: return allow()``. These tests pin the opposite: an
annotator that is down, a control that raises, and a point the policy
does not bind all end with the refund not happening.
"""

from __future__ import annotations

import pytest
from agent_hooks import Decision, HostError, Verdict
from app.annotators import LocalAnnotators
from app.host import RefundSession, activate

ORDINARY_REFUND = {"order_id": "A-1001", "amount": 40.0, "reason": "damaged"}


@pytest.fixture(scope="module")
def broken_policy():
    """A policy whose classifier is unreachable."""
    return activate(LocalAnnotators(fail=True))


class ExplodingControl:
    """A control with a bug in it."""

    def intercept(self, context):
        raise ZeroDivisionError("bug in a host control")


@pytest.mark.asyncio
async def test_a_failed_annotator_denies_rather_than_allowing(broken_policy):
    session = RefundSession(broken_policy, session_id="annotator-down")

    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)

    assert not guarded.proceeded
    assert guarded.reason == "runtime_error:annotation_failed"
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_a_control_that_raises_denies_and_leaves_the_others_registered(policy):
    session = RefundSession(
        policy,
        session_id="exploding",
        extra_controls=[("buggy", ExplodingControl())],
    )

    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)

    assert not guarded.proceeded
    assert guarded.reason == HostError.INTERCEPTOR_FAILED.value
    assert session.tools.ledger.entries == []
    # The failure is attributed to the control that caused it, and the
    # other two are still part of the emission rather than being disabled
    # to get past it.
    assert guarded.record.interceptors_registered == 3
    assert [v.name for v in guarded.record.verdicts] == ["acs", "budget", "buggy"]
    assert guarded.record.verdicts[2].reason == HostError.INTERCEPTOR_FAILED.value
    assert [v.decision for v in guarded.record.verdicts[:2]] == [
        Decision.ALLOW,
        Decision.ALLOW,
    ]


def test_an_unbound_point_denies_at_the_policy(policy):
    """``ActivatedPolicy`` fails closed on a point it does not bind."""
    context = {"interception_point": "post_tool_call", "tool_result": {"value": 1}}

    verdict = policy.evaluate("post_tool_call", context)

    assert verdict.decision is Decision.DENY
    assert verdict.reason == "runtime_error:intervention_point_unknown"


def test_the_bound_set_is_readable_rather_than_guessed(policy):
    assert policy.intervention_points == ("input", "pre_tool_call", "output")
    assert policy.governs("pre_tool_call")
    assert not policy.governs("agent_startup")


def test_an_invalid_point_name_is_a_boundary_error_not_a_verdict(policy):
    """A typo is the host's bug, so it raises instead of denying."""
    with pytest.raises(ValueError, match="unknown intervention point"):
        policy.evaluate("pre_tool", {"interception_point": "pre_tool"})


@pytest.mark.asyncio
async def test_scoping_is_explicit_and_does_not_weaken_the_bound_points(policy):
    """Allowing an ungoverned point is a scope statement, not a bypass."""
    session = RefundSession(policy, session_id="scope")

    startup = await session.startup(["lookup_order", "issue_refund"])
    assert startup.proceeded
    assert startup.record.verdict.decision is Decision.ALLOW

    # The points this version does bind still decide.
    blocked = await session.call_tool(
        "c1",
        "issue_refund",
        {"order_id": "A-1002", "amount": 50.0, "reason": "stolen card"},
    )
    assert not blocked.proceeded


@pytest.mark.asyncio
async def test_an_emitter_with_no_controls_fails_closed(policy):
    session = RefundSession(policy, session_id="empty")
    session.emitter._interceptors.clear()
    session.emitter._names.clear()

    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)

    assert not guarded.proceeded
    assert guarded.reason == HostError.NO_INTERCEPTOR.value


@pytest.mark.asyncio
async def test_a_control_returning_nonsense_is_rejected_not_trusted(policy):
    class Nonsense:
        def intercept(self, context):
            return {"decision": "definitely_fine"}

    session = RefundSession(
        policy, session_id="nonsense", extra_controls=[("nonsense", Nonsense())]
    )

    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)

    assert not guarded.proceeded
    assert guarded.record.verdict.reason.startswith("host_error:")
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_a_transform_cannot_invent_a_missing_field(policy):
    """A transform replaces a value; it cannot add an absent key."""

    class AddsAKey:
        def intercept(self, context):
            if context["interception_point"] != "pre_tool_call":
                return Verdict.allow()
            return Verdict.from_wire(
                {
                    "decision": "transform",
                    "reason": "force_dry_run",
                    "transform": {"path": "$target.dry_run", "value": True},
                }
            )

    session = RefundSession(
        policy, session_id="missing-key", extra_controls=[("dry", AddsAKey())]
    )

    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)

    assert not guarded.proceeded
    assert guarded.reason == HostError.TRANSFORM_INVALID.value
