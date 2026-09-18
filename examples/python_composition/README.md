# Two ACS policies at a tool boundary

Follow the [SDK README](../../sdk/python/README.md) for installation and
the [integration guide](../../docs/ACS-AND-AGENT-HOOKS.md) for the code changes.
From the repository root:

```bash
python examples/python_composition/compose.py
python -m unittest discover -s examples/python_composition -v
```

`limits.yaml` and `orders.yaml` load their respective Rego files from
`policy/`. `compose.py` builds a pre-tool context, runs both ACS controls,
and invokes an inert refund operation only when permitted.

The tests execute the guide's Python blocks and the SDK README snippets.
They also check transform visibility, denied invocations, evaluation errors,
unbound points, and approval stop/resume behavior. No private service,
annotator, or paid model is required.

Tested in a clean environment with published `agent-control-spec==0.4.0a3`,
`agent-hooks-sdk==0.1.0a5`, and CPython 3.12.3 on Linux x86-64.
The Python CI job runs these tests in a separate environment with the
published package, rather than the checkout's native build.

The example isolates `pre_tool_call` to show how to add enforcement at
one dispatch boundary. A complete host must retain its other lifecycle
hooks, including the matching `post_tool_call` after an executed tool.
These local synchronous policies run inline; they do not demonstrate
nonblocking evaluation or a complete framework integration.
