# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The host: the only place in this example that can stop anything.

ACS computes a verdict. agent-hooks aggregates verdicts and hands back
the effective target. Neither of them calls a tool, so neither of them
can prevent one. Enforcement is the three habits in this file:

1. Call the guarded operation only on the path where ``emit`` returned.
   ``emit`` raises ``InterceptionBlocked`` when the action must not
   proceed, so the tool call sits after the ``await`` and never executes
   on the blocked path.
2. Pass ``outcome.target`` to the operation, not the arguments the host
   built. A transform folds into the context during the emission, so a
   reference captured before ``emit`` can be stale by the time it
   returns.
3. Commit side effects only after they happen. The refund budget is
   charged after the tool returns, so a denied or blocked call leaves
   the budget untouched.

Ordering follows from the same idea. ``output`` is the last point at
which the reply can be changed, and it is strictly after any tool has
run: redacting a reply does not un-issue a refund. Anything that must
prevent an effect has to be bound before that effect, at
``pre_tool_call``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_control_spec import ActivatedPolicy
from agent_hooks import (
    AgentContextBuilder,
    ApprovalResolver,
    CompositionConfig,
    EnforcementMode,
    InterceptionBlocked,
    InterceptionEmitter,
    InterceptionRecord,
    Interceptor,
)

from .acs_control import AcsControl
from .annotators import LocalAnnotators
from .budget_control import RefundBudgetControl
from .tools import RefundTools

EXAMPLE_DIR = Path(__file__).resolve().parent.parent
MANIFEST_PATH = EXAMPLE_DIR / "manifest.yaml"


def activate(annotators: LocalAnnotators | None = None) -> ActivatedPolicy:
    """Ready one policy version.

    Do this once, at startup, off the serving path: activation reads the
    manifest, loads the Rego bundle and compiles each bound entrypoint,
    so that every later ``evaluate`` costs no I/O and no compile. The
    result is immutable and safe to share across sessions and threads.
    Changing the policy means activating again, which is the point. The
    host decides when a version changes.

    The annotator dispatcher is bound here, so it is shared by every
    caller of this activation and has to tolerate concurrent calls.
    """
    return ActivatedPolicy(
        str(MANIFEST_PATH),
        annotator_dispatcher=annotators
        if annotators is not None
        else LocalAnnotators(),
    )


@dataclass(frozen=True)
class Guarded:
    """What the host learned from one emission."""

    proceeded: bool
    record: InterceptionRecord
    value: Any = None

    @property
    def reason(self) -> str | None:
        return self.record.verdict.reason


class RefundSession:
    """One agent session: one emitter, one context builder, one budget.

    The emitter carries per-session state, the record buffer and the
    composition configuration, and the builder owns the sequence
    counter. They are session-scoped for that reason. The activated
    policy behind ``AcsControl`` is not: it is immutable and shared.

    Concurrency, stated plainly: this object is safe to use from one
    task at a time. Work that runs in a child task, a thread, or a
    subprocess needs its own session built from the same activation and
    the same session identity, so the required controls and the trusted
    context travel with it. Sharing one emitter across everything
    interleaves sequence numbers and record buffers between logically
    separate emissions.
    """

    def __init__(
        self,
        policy: ActivatedPolicy,
        *,
        session_id: str,
        budget_cap: float = 300.0,
        composition: CompositionConfig | None = None,
        resolver: ApprovalResolver | None = None,
        mode: EnforcementMode = EnforcementMode.ENFORCE,
        timeout: float | None = 5.0,
        record_sink: Callable[[InterceptionRecord], None] | None = None,
        extra_controls: Iterable[tuple[str, Interceptor]] = (),
    ) -> None:
        self.tools = RefundTools()
        self.budget = RefundBudgetControl(budget_cap)
        self.acs = AcsControl(policy)

        self.emitter = InterceptionEmitter(
            mode=mode,
            resolver=resolver,
            timeout=timeout,
            composition=composition
            if composition is not None
            else CompositionConfig.run_all(),
        )
        # Registration order is the dispatch order in the sequential
        # profiles. Policy evaluation first, then the host's own
        # mandatory control.
        self.emitter.register(self.acs, self.acs.name)
        self.emitter.register(self.budget, self.budget.name)
        for name, control in extra_controls:
            self.emitter.register(control, name)
        if record_sink is not None:
            self.emitter.set_record_sink(record_sink)

        self.builder = AgentContextBuilder(
            agent_id="refund-assistant",
            framework="guarded-refunds-example",
            session_id=session_id,
        )

    async def startup(self, tool_names: list[str]) -> Guarded:
        ctx = self.builder.agent_startup(tools_registered=tool_names)
        return await self._emit(ctx)

    async def handle_input(self, content: str) -> Guarded:
        ctx = self.builder.input(content=content)
        return await self._emit(ctx)

    async def call_tool(self, call_id: str, name: str, args: dict[str, Any]) -> Guarded:
        ctx = self.builder.pre_tool_call(call_id=call_id, name=name, args=args)
        guarded = await self._emit(ctx)
        if not guarded.proceeded:
            return guarded

        # The effective target, not `args`: a transform may have rewritten it.
        effective: Mapping[str, Any] = guarded.value
        value = self.tools.call(name, dict(effective))
        if name == "issue_refund":
            self.budget.commit(float(effective["amount"]))
        return Guarded(proceeded=True, record=guarded.record, value=value)

    async def reply(self, content: str) -> Guarded:
        ctx = self.builder.output(content=content)
        guarded = await self._emit(ctx)
        if not guarded.proceeded:
            return guarded
        return Guarded(
            proceeded=True, record=guarded.record, value=guarded.value["content"]
        )

    async def _emit(self, ctx: dict[str, Any]) -> Guarded:
        try:
            outcome = await self.emitter.emit(ctx)
        except InterceptionBlocked as blocked:
            return Guarded(proceeded=False, record=blocked.result)
        return Guarded(proceeded=True, record=outcome.record, value=outcome.target)
