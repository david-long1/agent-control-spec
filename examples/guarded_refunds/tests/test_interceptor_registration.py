# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``AcsInterceptor`` registered straight into an emitter.

The composition guide claims ACS needs no adapter, and that a partial
manifest stops a run at the first point it does not bind. Both are
asserted here, because the second one is the reason the example ships a
scoped control instead.
"""

from __future__ import annotations

import pytest
from agent_control_spec import AcsInterceptor
from agent_hooks import (
    AgentContextBuilder,
    CompositionConfig,
    InterceptionBlocked,
    InterceptionEmitter,
    Interceptor,
)
from app.annotators import LocalAnnotators
from app.host import MANIFEST_PATH


@pytest.fixture
def raw_emitter():
    interceptor = AcsInterceptor(
        str(MANIFEST_PATH), "acs", annotator_dispatcher=LocalAnnotators()
    )
    emitter = InterceptionEmitter(composition=CompositionConfig.run_all())
    emitter.register(interceptor, "acs")
    return emitter


@pytest.fixture
def builder():
    return AgentContextBuilder(
        agent_id="refund-assistant", framework="raw", session_id="raw"
    )


def test_acs_interceptor_is_an_agent_hooks_interceptor():
    interceptor = AcsInterceptor(
        str(MANIFEST_PATH), "acs", annotator_dispatcher=LocalAnnotators()
    )
    assert isinstance(interceptor, Interceptor)
    assert interceptor.name == "acs"


@pytest.mark.asyncio
async def test_a_bound_point_decides_normally(raw_emitter, builder):
    ctx = builder.pre_tool_call(
        call_id="c1",
        name="issue_refund",
        args={"order_id": "A-1002", "amount": 50.0, "reason": "stolen card"},
    )

    with pytest.raises(InterceptionBlocked) as blocked:
        await raw_emitter.emit(ctx)

    assert blocked.value.result.verdict.reason == "fraud_suspected"


@pytest.mark.asyncio
async def test_an_unbound_point_stops_the_run_at_startup(raw_emitter, builder):
    """Why the example wraps ACS instead of registering it directly.

    ``agent_startup`` is the first point a host emits, and this manifest
    does not bind it, so an unscoped ACS control ends the session before
    it begins. Bind all eight points, or scope the control.
    """
    ctx = builder.agent_startup(tools_registered=["issue_refund"])

    with pytest.raises(InterceptionBlocked) as blocked:
        await raw_emitter.emit(ctx)

    assert (
        blocked.value.result.verdict.reason
        == "runtime_error:intervention_point_unknown"
    )
