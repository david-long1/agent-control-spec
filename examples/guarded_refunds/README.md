# Guarded refunds

A support agent that can look up an order and issue a refund, wrapped in
two controls: an ACS policy and a host-owned spend cap. It is the worked
example for [the policy SDK guide](../../docs/POLICY-SDK.md) and for
[ACS and agent-hooks together](../../docs/ACS-AND-AGENT-HOOKS.md).

Everything runs offline. The tools write to an in-process ledger, the
classifiers are deterministic local functions, and nothing calls a model
or a paid service.

## Run

```bash
pip install -r examples/guarded_refunds/requirements.txt
python examples/guarded_refunds/app/demo.py
pytest examples/guarded_refunds/tests
```

Tested against the published packages `agent-control-spec==0.4.0a3` and
`agent-hooks-sdk==0.1.0a5` on CPython 3.12, Linux x86-64.

## What it shows

`manifest.yaml` binds three of the eight interception points on purpose,
so the example has to answer for the five it leaves unbound.

| Scenario | Outcome |
| --- | --- |
| Ordinary refund | allowed, ledger records it |
| Prompt injection at `input` | denied, the turn ends |
| Refund of 150 | transformed to 100, and the tool is called with 100 |
| Refund reason matching fraud | denied, ledger untouched |
| Reply containing an email address | transformed, address redacted |
| Refund above 200 | liftable deny, offered to an approver |
| Classifier unreachable | `runtime_error:annotation_failed`, denied |
| `agent_startup`, which the manifest does not bind | control declines to decide |
| Refund of -1000 | denied before the cap does arithmetic on it |
| A child task continuing the session | shares the one cap, not a fresh one |

## Files

| Path | What it is |
| --- | --- |
| `manifest.yaml` | Binds `input`, `pre_tool_call` and `output` |
| `policy/refund_guardrails.rego` | The rules, one entrypoint per bound point |
| `app/host.py` | The enforcement boundary, the only thing that can stop a tool; also turn state and `for_child_task` |
| `app/acs_control.py` | ACS as a scoped, bounded, awaitable control |
| `app/budget_control.py` | A mandatory host control that could not be an ACS policy, shared across a logical session |
| `app/annotators.py` | Deterministic classifier stubs, with knobs for slow and failing |
| `app/tools.py` | Inert tools and the ledger the tests assert on |
| `app/demo.py` | Prints one line per scenario, then checks the ledger |

## Tests

46 tests, about two seconds. They assert what the agent did rather than
what the verdict said. The deny tests check the ledger is empty, and the
transform test checks the tool ran against the rewritten amount.

| File | Covers |
| --- | --- |
| `test_verdicts.py` | allow, deny, transform write-back, and why `output` is too late to prevent an effect |
| `test_composition.py` | profiles, fold-through versus isolation, approval eligibility, stop versus resume, the two cases where the profile guidance has exceptions |
| `test_failures.py` | failing annotators, raising controls, unbound points, invalid verdicts, invalid refund amounts |
| `test_async.py` | event-loop blocking, timeout preemption, evaluation capacity, child sessions sharing a cap |
| `test_modes_and_records.py` | enforce versus evaluate-only, record contents, what identity does not prove |
| `test_interceptor_registration.py` | `AcsInterceptor` registered directly, and the partial-manifest trap |
