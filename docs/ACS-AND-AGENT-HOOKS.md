# ACS and agent-hooks together

Most hosts end up with more than one control: a policy engine, a spend
cap, a tenant allowlist, something a compliance team asked for last
quarter. This guide describes the canonical way to run ACS as one of
them.

The division of labour is the whole design. **agent-hooks owns
composition**: it dispatches the controls, combines their verdicts under
a profile you declare, consults the approval seam, folds transforms and
produces the record. **ACS evaluates policy**: one manifest, one
context, one verdict, no state between calls. You import both, and the
host is the only thing that can actually stop an action.

For ACS on its own, see [the policy SDK guide](POLICY-SDK.md). Either
guide can be read alone.

## Install

```bash
pip install "agent-control-spec==0.4.0a3"
```

which resolves to:

```
agent-control-spec==0.4.0a3
agent-hooks-sdk==0.1.0a5
```

agent-hooks arrives as an ACS dependency, and ACS pins it exactly
(`agent-hooks-sdk==0.1.0a5`). Installing it separately is fine but
unnecessary; asking for a different version gives you
`ResolutionImpossible` rather than a working environment. Every
published version of both packages is a pre-release, so pinning the
exact version means you do not need `--pre`. ACS requires Python 3.11 or
newer. Tested on CPython 3.12, Linux x86-64.

## Registering ACS as a control

`agent_control_spec.AcsInterceptor` already satisfies the agent-hooks
interceptor protocol, so there is no adapter:

```python
from agent_control_spec import AcsInterceptor
from agent_hooks import CompositionConfig, EnforcementMode, InterceptionEmitter

emitter = InterceptionEmitter(
    mode=EnforcementMode.ENFORCE,
    composition=CompositionConfig.run_all(),
)
emitter.register(AcsInterceptor("manifest.yaml"), "acs")
emitter.register(RefundBudgetControl(cap=300.0), "budget")  # your own control
```

`AcsInterceptor` is synchronous, which is fine when your policy is local
and fast. If it calls a classifier over the network, it will hold the
event loop for the whole round trip and the emitter's timeout will not
reach it, because only an awaitable return can be preempted. On an async
host, wrap an `ActivatedPolicy` instead and offload the call. The
example does this in `app/acs_control.py`, and the reasoning is in the
policy SDK guide.

The name you pass to `register` is payload-free and shows up on
`record.verdicts[].name`, so an entry says which control decided.

## Enforcement is three habits in the host

Neither library calls your tools, so neither can stop one. Enforcement
is what the host does with the result.

```python
from agent_hooks import InterceptionBlocked

try:
    outcome = await emitter.emit(ctx)
except InterceptionBlocked as blocked:
    return refusal(blocked.result)

result = tools.call(name, dict(outcome.target))   # effective target
budget.commit(outcome.target["amount"])           # commit after the effect
```

1. The guarded call sits after the `await`. `emit` raises
   `InterceptionBlocked` when the action must not proceed, so the
   blocked path never reaches the tool. If you prefer to branch instead
   of catching, `emit_unchecked` returns the record and you check
   `record.proceeds` yourself. Forgetting that check is then a one-line
   mistake, which is why `emit` is the default.
2. Pass `outcome.target`, not the arguments you built. A transform folds
   into the context during the emission, so a reference captured before
   `emit` can be stale when it returns. In the example, a request to
   refund 150 reaches the tool as 100.
3. Commit side effects after they happen. The refund budget is charged
   after the tool returns, so a blocked call leaves it untouched.

Ordering follows from the same idea. `output` is the last point at which
a reply can be changed, and it is strictly after any tool has run.
Redacting a reply does not un-issue a refund. A control that must
prevent an effect has to be bound before that effect, at
`pre_tool_call`.

## Profiles, and which one keeps your mandatory controls

The host declares how verdicts combine. It is configuration, chosen from
a closed set, and no returned verdict can influence it.

| Profile | Dispatch | Combined verdict |
| --- | --- | --- |
| `sequential/first_deny` | in order, transforms fold through | first deny short-circuits |
| `sequential/run_all` | in order, transforms fold through | severity maximum; only a transform that fails to apply short-circuits |
| `parallel/strictest` | each control gets the same untransformed snapshot | severity maximum |
| `parallel/unanimous` | isolated snapshots | allow only if all allowed |

"Parallel" names isolation, not scheduling. No control sees another's
transform, and a conformant host may still dispatch them one at a time.

The sequential profiles fold transforms through, and it changes
outcomes. In the example, ACS caps a 150 refund to 100 and the budget
control then sees 100 and allows it. Under `parallel/strictest` the
budget control sees the original 150 and denies. Same controls, same
request, opposite result, so pick the profile deliberately. Fold-through
is right when a later control should judge what will actually happen.
Isolation is right when controls must not be able to soften each other.

`run_all` runs every control, with one exception worth knowing: a
transform that cannot be applied is a host error, and both sequential
profiles stop there. A control registered after the one that produced
the bad transform does not run. So `run_all` is much stronger than
`first_deny` for mandatory controls without being an absolute guarantee
that everything was consulted; read `verdicts[]` on the record if you
need to know.

The default is `sequential/first_deny` with `on_approval: stop`. It is a
reasonable default and a poor fit for mandatory controls, for the reason
in the next section.

## Approval, and the controls that never ran

A liftable deny is a deny carrying an `approval` block. The host may
register a resolver for it; with no resolver, a liftable deny is simply
enforced as a deny, which is conformant rather than an error.

When the seam gets consulted depends on the profile:

- `sequential/first_deny` consults at the first deny it hits, if that
  deny is liftable.
- `sequential/run_all` and the parallel profiles run every control
  first, then consult at most once, and only when the aggregate winner
  is liftable.

Under the first two of those, a plain deny wins outright and is never
offered for approval. `parallel/unanimous` is the exception, and it is
easy to miss: with `on_disagreement: approval`, one control allowing and
another denying outright is a *disagreement*, and the host synthesizes a
liftable deny from it. An approver can then permit an action that a
control refused. If a deny from any control has to be final, use
`on_disagreement: deny`, which is the default. Both halves are in
`tests/test_composition.py::test_unanimous_with_approval_can_lift_a_plain_deny`.

Under `first_deny`, the `on_approval` knob decides what a lifted deny
does to the rest of the fold. `stop` ends the emission there; `resume`
substitutes the resolution and carries on. This is the part that
surprises people, so here it is measured. One escalating refund of 250,
a budget control registered second with only 50 left, and an approver
that says yes:

| Profile | Budget control ran | Refunded |
| --- | --- | --- |
| `sequential/run_all` | yes | 0 |
| `sequential/first_deny` + `stop` | **no** | **250** |
| `sequential/first_deny` + `resume` | yes | 0 |

With `stop`, an approver lifting the ACS escalation ended the emission
before the budget control was ever asked, and the refund went through.
Nothing malfunctioned; the profile did what it says. The record is
honest about it, setting `fold_truncated` to `true`, but the money had
already moved.

So: if a control must always run, use `sequential/run_all` or a parallel
profile. If you want `first_deny`, either register the mandatory
controls *before* anything that can escalate, or set
`on_approval: resume`. Reproduced in
`tests/test_composition.py::test_first_deny_with_stop_skips_a_later_mandatory_control`.

Two aggregation policies are specified as rejected and must not be
implemented: most-permissive-wins, because one lax control would
silently bypass every other, and k-of-n quorum, because it silently
overrides the controls that disagreed, on every single action, in
exchange for a weak security story.

## Scope, when the manifest does not cover everything

A host emits the interception points its capabilities cover, and a host
with a tool loop emits the full set. An ACS manifest binds whichever it
declares and denies the rest with
`runtime_error:intervention_point_unknown`. Since `agent_startup` comes
first, a partial manifest under an unscoped ACS control stops the run
immediately.

Bind all eight points if you want one policy answer everywhere.
Otherwise scope the control explicitly:

```python
self._governed = frozenset(policy.intervention_points)

async def intercept(self, context):
    if context["interception_point"] not in self._governed:
        return Verdict.allow()
    ...
```

Returning `allow` there means *this control has no opinion here*, not
*nothing governs this point*. The other registered controls still run
and the profile still aggregates, which is precisely why the narrow
statement is safe. Catching an ACS deny and converting it to an allow is
not the same thing and is never safe: it erases the difference between
silence and failure.

## When a control breaks

A control that raises becomes a fail-closed deny attributed to that
control, and the emission still lists every control that was registered.
Nothing gets disabled to keep the run going.

```python
assert guarded.record.verdict.reason == "host_error:interceptor_failed"
assert guarded.record.interceptors_registered == 3
```

The same holds for a control returning something that is not a valid
verdict, for a transform naming an absent key
(`host_error:transform_invalid`), and for an emitter with no controls
registered at all (`host_error:no_interceptor`). An empty emitter fails
closed rather than passing everything, so a deliberate passthrough has
to be an explicitly registered allow-all.

If you want a control's failure to be survivable, say so in the
configuration rather than by wrapping it in a bare `except`. Note that
`register()` takes an interceptor and a name and nothing else: the
`timeout` is one emitter-wide setting, so "give the flaky control a
looser deadline" is not something the published API offers. What you can
choose is the profile, and whether that control's deny decides the
emission.

## Enforce, evaluate-only, and what a record is

`EnforcementMode.EVALUATE_ONLY` is a measurement mode. Verdicts are
computed and recorded, and nothing is acted on: a deny is recorded and
the refund still happens, a transform is validated and not applied. It
answers "what would this policy have done to last week's traffic", and
it is not a quiet way to enforce.

Records are payload-free by design. They carry the point, the mode, the
composition in effect, per-control verdict summaries, and SHA-256
identities, but not the content that was governed:

```python
{'mode': 'enforce',
 'verdict': {'decision': 'deny', 'reason': 'fraud_suspected', ...},
 'input_identity': 'sha256:596de09e...',
 'identity_provider': 'jcs-sha256',
 'composition': {'profile': 'sequential/run_all'}}
```

One caveat on "payload-free". The record drops the context and a
transform's value, but `reason`, `message` and any warnings are strings
the *policy* wrote. Nothing stops a rule from interpolating the governed
text into a message, and it would then travel to every sink. Keep policy
metadata payload-free at the source; the record's guarantee is about the
projection, not about what your rules put in it.

That buffer is not an audit log. `set_max_records` drops the **oldest**
record when the bound is reached and increments `records_dropped`, and a
record sink that raises is swallowed so audit trouble cannot take down
the control plane. Durable, ordered, tamper-evident storage is yours to
build; `set_record_sink` is where you hand records to it, and
`take_records` drains the buffer on a long session.

`context_identity` is a fingerprint, not an authentication. The
`jcs-sha256` projection is closed: it covers the fields each point marks
required and excludes optional envelope data such as `actor`, `tenant`
and `trace`. A context claiming a privileged role hashes identically to one that does
not. The identity proves which content a
decision was made about, and says nothing about who asked. Authenticate
callers before you build the context.

## Sessions, threads and background work

The activated policy is immutable and shared. The emitter is not.

An emitter holds the record buffer and the composition in effect, and
the context builder owns the sequence counter, so both are per session.
Work that continues in a child task, a worker thread or a subprocess
needs its own emitter and builder. Sharing one emitter across everything
interleaves sequence numbers and record buffers between unrelated
emissions.

What the child must *not* get is its own copy of the controls. Rebuild a
stateful control and you have handed the child a second full budget, a
second rate limit, a second counter, and the limit you thought you had
is now per emitter rather than per session. Pass the same control
instances through, along with the same activation, and make them safe to
call from more than one place. The example does this in
`RefundSession.for_child_task`, and
`tests/test_async.py::test_rebuilding_a_session_instead_would_hand_out_a_second_budget`
shows what the careless version costs: 160 refunded against a cap of
120.

The annotator dispatcher is bound at activation, so it is shared by
every caller of that activation and has to tolerate concurrent calls.

## Run it

```bash
pip install -r examples/guarded_refunds/requirements.txt
python examples/guarded_refunds/app/demo.py
pytest examples/guarded_refunds/tests
```

`app/host.py` is the enforcement boundary, `app/acs_control.py` the
scoped async ACS control, `app/budget_control.py` a mandatory host
control that could not be an ACS policy because it is stateful by
nature. `tests/test_composition.py` holds the profile behaviour above.
