# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Modes, records, and identity -- three things that are easy to overclaim."""

from __future__ import annotations

import pytest
from agent_hooks import (
    AgentContextBuilder,
    EnforcementMode,
    canonical_json,
    context_identity,
)
from app.host import RefundSession

FRAUDULENT_REFUND = {"order_id": "A-1002", "amount": 50.0, "reason": "stolen card"}
LARGE_REFUND = {"order_id": "A-1003", "amount": 150.0, "reason": "late delivery"}


@pytest.mark.asyncio
async def test_evaluate_only_records_a_deny_and_still_lets_it_happen(policy):
    """``evaluate_only`` is a measurement mode, not a quiet enforcement mode."""
    session = RefundSession(policy, session_id="eo", mode=EnforcementMode.EVALUATE_ONLY)

    guarded = await session.call_tool("c1", "issue_refund", FRAUDULENT_REFUND)

    assert guarded.proceeded
    assert guarded.record.verdict.reason == "fraud_suspected"
    assert guarded.record.mode is EnforcementMode.EVALUATE_ONLY
    # The verdict was recorded. The refund happened anyway.
    assert session.tools.ledger.total == 50.0


@pytest.mark.asyncio
async def test_evaluate_only_does_not_apply_a_transform_either(policy):
    session = RefundSession(
        policy, session_id="eo-transform", mode=EnforcementMode.EVALUATE_ONLY
    )

    guarded = await session.call_tool("c1", "issue_refund", LARGE_REFUND)

    assert guarded.value == {"refunded": 150.0, "order_id": "A-1003"}
    assert session.tools.ledger.total == 150.0


@pytest.mark.asyncio
async def test_enforce_is_the_same_policy_with_a_different_outcome(policy):
    session = RefundSession(policy, session_id="enforce", mode=EnforcementMode.ENFORCE)

    guarded = await session.call_tool("c1", "issue_refund", FRAUDULENT_REFUND)

    assert not guarded.proceeded
    assert session.tools.ledger.total == 0.0


@pytest.mark.asyncio
async def test_records_are_payload_free(policy):
    delivered = []
    session = RefundSession(policy, session_id="records", record_sink=delivered.append)

    await session.call_tool("c1", "issue_refund", FRAUDULENT_REFUND)

    wire = delivered[0].to_wire()
    serialized = canonical_json(wire)
    assert "stolen card" not in serialized
    assert "A-1002" not in serialized
    assert wire["input_identity"].startswith("sha256:")
    assert wire["composition"]["profile"] == "sequential/run_all"


@pytest.mark.asyncio
async def test_the_in_memory_buffer_is_a_buffer_not_an_audit_log(policy):
    """Records are dropped silently when the bound is reached."""
    session = RefundSession(policy, session_id="buffer")
    session.emitter.set_max_records(1)

    await session.call_tool("c1", "issue_refund", FRAUDULENT_REFUND)
    await session.call_tool("c2", "issue_refund", FRAUDULENT_REFUND)

    assert len(session.emitter.results) == 1
    assert session.emitter.records_dropped == 1


@pytest.mark.asyncio
async def test_a_failing_sink_does_not_fail_the_emission(policy):
    """Audit delivery is the host's problem; the control plane keeps going."""

    def broken_sink(record):
        raise OSError("audit store unavailable")

    session = RefundSession(policy, session_id="sink", record_sink=broken_sink)

    guarded = await session.call_tool("c1", "issue_refund", FRAUDULENT_REFUND)

    # The deny still held -- but nothing durable was written, and the
    # host was not told. Durability is the host's to build.
    assert not guarded.proceeded


def test_context_identity_fingerprints_content_not_the_caller():
    """It binds a decision to what was decided on. It authenticates nobody.

    The ``jcs-sha256`` projection is closed: it covers the fields each
    point marks required, and excludes optional envelope data such as
    ``actor``, ``tenant`` and ``trace``. So a context claiming a
    privileged role hashes identically to one that does not, while
    changing the actual tool arguments changes the identity.
    """
    builder = AgentContextBuilder(
        agent_id="refund-assistant", framework="test", session_id="identity"
    )
    honest = builder.pre_tool_call(
        call_id="c1", name="issue_refund", args={"amount": 40.0}
    )
    honest["actor"] = {"id": "agent-runner", "kind": "service"}

    forged = dict(honest)
    forged["actor"] = {"id": "treasury-admin", "kind": "human"}

    bigger = dict(honest)
    bigger["target"] = {"amount": 4000.0}
    bigger["tool_call"] = {**honest["tool_call"], "args": {"amount": 4000.0}}

    # The role claim does not reach the identity at all, so no amount of
    # checking the identity will tell a host who asked.
    assert context_identity(honest) == context_identity(forged)
    # What is governed does reach it.
    assert context_identity(honest) != context_identity(bigger)
    assert context_identity(honest).startswith("sha256:")
