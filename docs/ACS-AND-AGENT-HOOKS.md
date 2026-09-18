# Compose ACS evaluations through Agent Hooks

ACS evaluates each policy and returns a verdict. Agent Hooks dispatches
the controls, combines their verdicts, and applies transforms. The host
enforces the result by deciding whether to call the operation and which
arguments to pass.

## Run the example

Follow the [Python SDK README](../sdk/python/README.md) for installation
and activation. From the repository root:

```bash
python examples/python_composition/compose.py
python -m unittest discover -s examples/python_composition -v
```

The example uses two native `AcsInterceptor` instances:

- `limits.yaml` caps a positive refund at 100 and denies invalid amounts.
- `orders.yaml` permits only orders `A-1001` and `A-1003`, with an amount
  greater than zero and no more than 100.

Each manifest binds only `pre_tool_call` and points to its own Rego file.
There are no annotators, external services, or payments. The operation
appends its arguments to a local ledger.

## Select the composition profile

The example explicitly uses `CompositionConfig.run_all()` in `ENFORCE`
mode and registers `limits` before `orders`. This
`sequential/run_all` profile lets the order policy evaluate the amount
that will actually be refunded, including an earlier cap.

Agent Hooks calls both controls in order. An ordinary deny does not
stop dispatch. Permitted transforms are applied before the next control,
including the `tool_call.args` that ACS reads. The aggregate selects the
highest severity: deny, then transform, then allow. A transform that
cannot be applied stops the fold with a host-error denial.

With `parallel/strictest`, both controls would instead receive isolated
copies of the original context. The order policy would see 150 and deny,
even if the limit policy proposed reducing it to 100.

## Enforce and inspect the result

[`compose.py`](../examples/python_composition/compose.py) constructs the
full context with `AgentContextBuilder.pre_tool_call()`. Its `refund`
function calls `await emitter.emit(context)` before invoking the tool.
If that raises `InterceptionBlocked`, it returns the denial record
without executing the operation. Otherwise, it passes `outcome.target`
to `issue_refund`, not the arguments captured before evaluation.

The expected results are:

| Request | Limits | Orders | Combined | Operation |
| --- | --- | --- | --- | --- |
| `A-1001`, 40 | allow | allow | allow | receives 40 |
| `blocked-order`, 40 | allow | deny | deny | never called |
| `A-1003`, 150 | transform | allow | transform | receives 100 |

The script prints `record.verdict.decision` and `record.proceeds`, plus
each entry's `name` and `decision` from `record.verdicts`. These
contributions identify which controls ran; the final ledger verifies
which operations executed. Records are in memory, not durable audit storage.

## Approvals and limits

This example has no approval resolver, and its policies never request
approval. Under `run_all`, a plain deny takes precedence over a liftable
deny; only an eligible aggregate reaches a configured resolver.

The default `first_deny` profile behaves differently: with
`on_approval: stop`, approval can end the fold before later controls run.
`OnApproval.RESUME` continues after a permitted resolution, but a standing
deny still stops dispatch. Do not rely on the default when later controls
must participate.

The second policy here only allows or denies, so it cannot rewrite a
value after checking it. If you add a later transform or allow an approval
resolver to transform arguments, revalidate required constraints on the
final target before executing.

Tested with published ACS `0.4.0a3`, Agent Hooks `0.1.0a5`, and CPython
3.12.3 on Linux x86-64. This is a single pre-tool example, not a complete
agent lifecycle integration. Its local synchronous policies execute inline;
the SDK README explains the async and unbound-point caveats.
