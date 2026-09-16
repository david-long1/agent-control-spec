# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Async behaviour: event-loop occupancy, timeouts and capacity.

``ActivatedPolicy.evaluate`` is synchronous. Calling it from a coroutine
occupies the event-loop thread for its full duration, and the emitter's
timeout cannot preempt it, because only an awaitable return is
preemptible. Offloading to a worker thread fixes both. That is what
these tests measure.

What they do *not* measure is native GIL release. The latency here is a
``time.sleep`` inside the Python annotator stub, and ``time.sleep``
releases the GIL by itself, so these assertions would pass against a
policy that never entered the engine at all. They are about where the
call runs, not about what the engine does while it runs.

Timings are deliberately coarse, a 300 ms stub against a 5 ms tick, so
the assertions describe behaviour rather than machine speed.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from agent_hooks import HostError, Verdict
from app.annotators import LocalAnnotators
from app.host import RefundSession, activate

SLOW_S = 0.3
TICK_S = 0.005
ORDINARY_REFUND = {"order_id": "A-1001", "amount": 40.0, "reason": "damaged"}


@pytest.fixture(scope="module")
def slow_policy():
    return activate(LocalAnnotators(latency_s=SLOW_S))


class InlineAcsControl:
    """The shape to avoid: evaluation called straight from the loop."""

    def __init__(self, policy) -> None:
        self._policy = policy
        self._governed = frozenset(policy.intervention_points)

    def intercept(self, context):
        point = context["interception_point"]
        if point not in self._governed:
            return Verdict.allow()
        return self._policy.evaluate(point, context)


async def _ticks_during(coro) -> tuple[int, object]:
    """Run ``coro`` while a second task tries to tick every 5 ms."""
    ticks = 0
    done = asyncio.Event()

    async def heartbeat():
        nonlocal ticks
        while not done.is_set():
            ticks += 1
            await asyncio.sleep(TICK_S)

    beat = asyncio.ensure_future(heartbeat())
    try:
        result = await coro
    finally:
        done.set()
        await beat
    return ticks, result


@pytest.mark.asyncio
async def test_offloaded_evaluation_leaves_the_loop_running(slow_policy):
    session = RefundSession(slow_policy, session_id="offloaded", timeout=None)

    ticks, guarded = await _ticks_during(
        session.call_tool("c1", "issue_refund", ORDINARY_REFUND)
    )

    assert guarded.proceeded
    # ~60 ticks are available in 300 ms; anything well above a handful
    # shows the loop was never parked.
    assert ticks > 10


@pytest.mark.asyncio
async def test_inline_evaluation_parks_the_whole_loop(slow_policy):
    """Same policy, same stub, synchronous call: nothing else runs."""
    session = RefundSession(slow_policy, session_id="inline", timeout=None)
    session.emitter._interceptors[0] = InlineAcsControl(slow_policy)

    ticks, guarded = await _ticks_during(
        session.call_tool("c1", "issue_refund", ORDINARY_REFUND)
    )

    assert guarded.proceeded
    assert ticks <= 2


@pytest.mark.asyncio
async def test_the_emitter_timeout_preempts_an_offloaded_evaluation(slow_policy):
    session = RefundSession(slow_policy, session_id="timeout", timeout=0.05)

    started = time.perf_counter()
    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)
    elapsed = time.perf_counter() - started

    assert not guarded.proceeded
    assert guarded.reason == HostError.INTERCEPTOR_TIMEOUT.value
    assert elapsed < SLOW_S
    # A timeout is a failure, so the refund does not happen.
    assert session.tools.ledger.entries == []


@pytest.mark.asyncio
async def test_the_emitter_timeout_does_not_reach_a_synchronous_control(slow_policy):
    """The timeout is configured and ignored: the call is not awaitable."""
    session = RefundSession(slow_policy, session_id="unpreemptible", timeout=0.05)
    session.emitter._interceptors[0] = InlineAcsControl(slow_policy)

    started = time.perf_counter()
    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)
    elapsed = time.perf_counter() - started

    assert guarded.proceeded
    assert guarded.reason != HostError.INTERCEPTOR_TIMEOUT.value
    assert elapsed >= SLOW_S


@pytest.mark.asyncio
async def test_a_timed_out_evaluation_keeps_its_permit_until_the_worker_finishes(
    slow_policy,
):
    """Capacity is released on completion, not on the host giving up."""
    session = RefundSession(slow_policy, session_id="capacity", timeout=0.05)

    guarded = await session.call_tool("c1", "issue_refund", ORDINARY_REFUND)
    assert guarded.reason == HostError.INTERCEPTOR_TIMEOUT.value

    # The host has stopped waiting; the worker has not stopped working.
    assert session.acs.evaluations_in_flight == 1
    await asyncio.sleep(SLOW_S)
    assert session.acs.evaluations_in_flight == 0


@pytest.mark.asyncio
async def test_concurrent_sessions_share_one_activation(policy):
    """The activated policy is immutable; the emitters are not shared."""
    sessions = [RefundSession(policy, session_id=f"s{i}") for i in range(4)]

    results = await asyncio.gather(
        *(
            session.call_tool("c1", "issue_refund", ORDINARY_REFUND)
            for session in sessions
        )
    )

    assert all(guarded.proceeded for guarded in results)
    assert all(session.tools.ledger.total == 40.0 for session in sessions)
    # Each session keeps its own sequence numbering.
    assert {guarded.record.sequence for guarded in results} == {0}
    assert len({guarded.record.session_id for guarded in results}) == 4


@pytest.mark.asyncio
async def test_a_child_session_shares_the_cap_it_inherits(policy):
    """Required controls have to survive work that continues elsewhere.

    A child task needs its own emitter and builder, because those hold
    per-emission state. It must not get its own budget: ``for_child_task``
    keeps the activation, the controls and the tools, so one logical
    session has one cap however many emitters it spans.
    """
    parent = RefundSession(policy, session_id="parent", budget_cap=120.0)
    child = parent.for_child_task(suffix="background")

    assert child.budget is parent.budget
    assert child.tools is parent.tools

    first = await parent.call_tool(
        "c1",
        "issue_refund",
        {"order_id": "A-1001", "amount": 80.0, "reason": "damaged"},
    )
    second = await child.call_tool(
        "c2", "issue_refund", {"order_id": "A-1003", "amount": 80.0, "reason": "late"}
    )

    assert first.proceeded
    assert not second.proceeded
    assert second.reason == "refund_budget_exceeded"
    assert parent.tools.ledger.total == 80.0
    # Separate record streams, both naming the same parent session.
    assert child.session_id == "parent/background"


@pytest.mark.asyncio
async def test_rebuilding_a_session_instead_would_hand_out_a_second_budget(policy):
    """Why ``for_child_task`` exists, shown by doing it the wrong way."""
    parent = RefundSession(policy, session_id="parent", budget_cap=120.0)
    rebuilt = RefundSession(policy, session_id="parent", budget_cap=120.0)

    await parent.call_tool(
        "c1",
        "issue_refund",
        {"order_id": "A-1001", "amount": 80.0, "reason": "damaged"},
    )
    escaped = await rebuilt.call_tool(
        "c2", "issue_refund", {"order_id": "A-1003", "amount": 80.0, "reason": "late"}
    )

    assert escaped.proceeded
    assert (
        parent.budget.committed + rebuilt.budget.committed == 160.0
    )  # over one 120 cap
