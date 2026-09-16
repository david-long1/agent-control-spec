# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The ACS-backed control, as an agent-hooks interceptor.

Two things here are deliberate and are the subject of the guides.

**Scope.** This manifest binds three of the eight interception points.
``ActivatedPolicy`` fails closed on the other five, which is correct for
a policy runtime and wrong as a whole-host answer, because the host
emits all eight. The adapter reads ``intervention_points`` once and
returns a plain ``allow`` for points this policy version does not bind.
That is this control declaring no opinion, not the host deciding no
policy applies: the other registered controls still run and the
composition profile still aggregates. A host that would rather have one
answer per point should bind all eight in the manifest instead, and then
this branch never fires.

**Concurrency.** ``ActivatedPolicy.evaluate`` is synchronous and
releases the GIL. Releasing the GIL lets other threads run; it does not
free the event-loop thread that is executing the call. An interceptor
that calls ``evaluate`` inline on the loop blocks every other task in
the process, and the emitter's timeout cannot preempt it, because only
an awaitable return is preemptible. Offloading to a worker thread makes
the call awaitable, so the loop keeps running and the emitter's timeout
applies.

The semaphore bounds how many evaluations are in flight. A timeout
cancels the host's wait, not the worker: the thread runs to completion
whatever the loop does. The permit is therefore released from a
completion callback on the shielded task rather than by leaving an
``async with`` block, so a run of slow evaluations cannot hand out more
permits than there are threads actually free.

The in-SDK version of this pattern is ``AsyncAcsInterceptor``, proposed
in responsibleai/agent-control-spec#68. It is not in a published
release, so this example uses the published API directly.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from agent_control_spec import ActivatedPolicy
from agent_hooks import Verdict


class AcsControl:
    """Bounded, scoped, awaitable interceptor over one activated policy."""

    def __init__(
        self,
        policy: ActivatedPolicy,
        *,
        name: str = "acs",
        max_concurrent_evaluations: int = 8,
    ) -> None:
        self._policy = policy
        self._name = name
        self._governed = frozenset(policy.intervention_points)
        self._slots = asyncio.Semaphore(max_concurrent_evaluations)
        self._in_flight = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def governed_points(self) -> frozenset[str]:
        return self._governed

    @property
    def evaluations_in_flight(self) -> int:
        """Workers still running, including ones the host stopped waiting for."""
        return self._in_flight

    async def intercept(self, context: Mapping[str, Any]) -> Verdict:
        point = context["interception_point"]
        if point not in self._governed:
            return Verdict.allow()

        await self._slots.acquire()
        self._in_flight += 1
        work = asyncio.ensure_future(
            asyncio.to_thread(self._policy.evaluate, point, context)
        )
        work.add_done_callback(self._release)
        # Shielded: a timeout ends the host's wait and the emitter fails
        # the emission closed, while the worker finishes on its own and
        # gives its permit back then.
        return await asyncio.shield(work)

    def _release(self, work: asyncio.Future[Verdict]) -> None:
        self._in_flight -= 1
        self._slots.release()
        if not work.cancelled():
            # Retrieve the outcome of a call nobody is waiting for any
            # more. The awaiting caller still sees the exception; this
            # only stops an abandoned task from warning at collection.
            work.exception()
