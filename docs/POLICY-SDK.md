# The ACS policy and evaluation SDK

ACS is a policy decision runtime. You give it a manifest, hand it one
agent context at a time, and get back a verdict. It never calls a tool,
never calls a model, and never writes an audit record, so it can be
dropped into a host without taking anything over.

This guide covers the Python binding, because Python is where the
runnable example lives. The runtime is the same engine behind the Node
and .NET bindings, and the manifest and policy are identical across
them, but nothing here was tested in another language.

For running ACS alongside other controls, see
[ACS and agent-hooks together](ACS-AND-AGENT-HOOKS.md). Either guide can
be read on its own.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install "agent-control-spec==0.4.0a3"
```

That one line installs everything:

```
agent-control-spec==0.4.0a3
agent-hooks-sdk==0.1.0a5
```

`agent-hooks-sdk` arrives as a declared dependency and resolves on its
own. You do not need `--no-deps`, and `pip check` passes. Older notes
recommending `--no-deps` describe a version conflict that no longer
exists; following that advice now hides real conflicts instead.

Every published version is a pre-release, so pip installs one without
`--pre`. You still need `--pre` to *discover* versions, because `pip index
versions agent-control-spec` reports no matching distribution without
it, and with any resolver configured to exclude pre-releases. Pinning the
exact version, as above, sidesteps both.

Published wheels are `cp311-abi3` for ACS and `cp310-abi3` for
agent-hooks, and the ACS metadata requires Python 3.11 or newer. The
examples below were run on CPython 3.12 on Linux x86-64.

Two version facts worth pinning down before writing a manifest:

```python
>>> import agent_control_spec as acs
>>> acs.__version__
'0.4.0a3'
>>> acs.supported_manifest_versions()
('0.4.0-alpha.1',)
```

Read `supported_manifest_versions()` rather than hardcoding the string.
A manifest declaring anything else is rejected at activation.

Published releases lag `main`. Anything you read in the repository's
source tree may not be in the version you installed. Check the
installed package, not the branch.

## Activate once, evaluate many times

```python
from agent_control_spec import ActivatedPolicy

policy = ActivatedPolicy("manifest.yaml", annotator_dispatcher=MyAnnotators())
verdict = policy.evaluate("pre_tool_call", context)
```

Activation reads the manifest, loads the Rego bundle and compiles the
entrypoint each bound point queries. Evaluation after that costs no
file I/O and no compilation. Do the activation at startup, off the
serving path, and keep the instance: it is immutable, and one instance
serves concurrent callers.

Editing the policy on disk changes nothing until you activate again.
That is the intended behaviour rather than a caching bug. The host
decides when a policy version changes, so a half-written file cannot
become the live policy.

If your manifests and Rego live in a database rather than on disk,
`ActivatedPolicy.from_memory(manifest_yaml, bundles)` takes both as
values and stages nothing to a temporary directory.

## What comes back

`evaluate` returns an agent-hooks `Verdict`. There are three decisions.

| Decision | What the host does |
| --- | --- |
| `allow` | run the action |
| `deny` | do not run the action |
| `transform` | run the action against the replacement value |

A policy may also express `warn` and `escalate`. The runtime normalizes
them: `warn` becomes an `allow` carrying a warning, and `escalate`
becomes a `deny` carrying an `approval` block. A deny with that block is
a *liftable* deny, meaning one a person is allowed to overturn. Check
`verdict.is_liftable` rather than looking for the word "escalate", which
never appears in a verdict.

A `transform` carries a single `{path, value}` replacement rooted at
`$target`. The runtime validates the path and hands it back; applying it
is the host's job. Two consequences that cost people an afternoon:

- A transform replaces a value. It cannot add a key that is absent, so a
  field you intend to govern has to be present in the first place.
  Declare it as a required tool parameter and always send it.
- The value the operation receives is the replacement, not the original.
  If the host keeps its own reference to the arguments and passes that,
  the transform is recorded and ignored.

## Bound and unbound points

A manifest binds whichever of the eight interception points it declares,
and no others. Ask, rather than assuming:

```python
>>> policy.intervention_points
('input', 'pre_tool_call', 'output')
>>> policy.governs("agent_startup")
False
```

Evaluating a point the version does not bind is not a quiet pass. It is
a fail-closed deny:

```python
>>> policy.evaluate("post_tool_call", context).reason
'runtime_error:intervention_point_unknown'
```

This is right for a policy runtime and wrong as a whole-host answer,
because a host emits all eight points whether your manifest mentions
them or not. You have two honest options:

1. **Bind all eight points in the manifest**, with a default `allow` for
   the ones you do not care about. The policy then has an answer for
   everything the host asks.
2. **Scope the caller explicitly**, reading `intervention_points` once
   and declining to evaluate outside that set.

What you should not do is catch the deny and convert it to an allow.
That erases the distinction between "this policy has no opinion here"
and "this policy failed", and the second one is the case that matters.

A misspelled point name is a different thing entirely. It is a bug in
your code rather than a policy outcome, so it raises `ValueError`
instead of returning a verdict.

## Failures fail closed

Every failure inside evaluation comes back as a `deny` with a reserved
`runtime_error:` reason. A classifier that is down, a policy that will
not run, a manifest that turns out to be broken: all of them deny.

```python
>>> policy.evaluate("pre_tool_call", context).reason
'runtime_error:annotation_failed'
```

Only boundary problems raise: an unknown point name, or a context that
will not serialize to JSON.

So `except Exception: return allow()` around `evaluate` does not make
your integration more robust. It converts every genuine failure into a
silent pass, and because the failures already arrived as denies, the
only thing that clause can catch is your own bug.

## Annotators are where the I/O goes

The runtime performs no I/O of its own. Anything that needs the network
(a content classifier, an LLM judge, a lookup) is an annotator, and the
host supplies the dispatcher:

```python
class MyAnnotators:
    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
        target = preliminary_policy_input["policy_target"]["value"]
        ...
        return {"label": "clear"}
```

The return value appears to the policy under
`input.annotations.<name>`. It can be any JSON value, so returning an
object lets a policy act on more than a label. The example's PII
annotator returns both a verdict label and the redacted text, which the
policy then names as a transform value.

Two things to hold on to. Annotators run only where a manifest point
*asks* for them, so eight bound points do not imply eight classifier
calls. And a dispatcher that raises does not silently no-op: the
evaluation denies with `runtime_error:annotation_failed`. Timeouts,
retries and caching belong in the dispatcher, because that is the only
place that knows what it is calling.

## Threads and event loops

`evaluate` is synchronous and releases the GIL while it runs. Those are
two different claims and only the first one constrains your design.

Releasing the GIL means other Python *threads* make progress during an
evaluation, which is why one activated policy can serve a thread pool.
It does not make the call asynchronous. Called directly from a coroutine
it occupies the event-loop thread for its full duration, and every other
task in the process waits, including the timeout meant to bound it.

On an async host, hand the call to a worker thread:

```python
verdict = await asyncio.to_thread(policy.evaluate, point, context)
```

Bound how many of those run at once, and budget the parts separately:
bundled HTTP annotators take a `timeout_ms`, the Rego runner reads
`ACS_OPA_TIMEOUT_MS` at initialization, and `manifest_url_timeout_ms`
bounds loading rather than evaluation. There is no single
whole-pipeline deadline, so a host that needs one composes it from
annotation time, evaluation time and its own callbacks.

An in-SDK version of this adapter is proposed in
[agent-control-spec#68](https://github.com/responsibleai/agent-control-spec/pull/68).
It is not in any published release, so build the adapter in your host
for now.

## Checking a manifest before you ship it

```python
from agent_control_spec import ManifestInvalidError, validate_manifest_file

try:
    validate_manifest_file("manifest.yaml")
except ManifestInvalidError as error:
    print(error)  # names the offending field
```

Use `validate_manifest_file` rather than `validate_manifest` whenever a
manifest uses `extends`: validation checks references across the merged
document, so a fragment cannot be judged from its own source.

## The worked example

`examples/guarded_refunds/` is a refund agent with a three-point
manifest, deterministic local classifiers, and inert tools. It runs
offline and calls no paid service.

```bash
pip install -r examples/guarded_refunds/requirements.txt
python examples/guarded_refunds/app/demo.py
pytest examples/guarded_refunds/tests
```

40 tests, about two seconds. They assert what the agent did rather than
what the verdict said. The deny tests check that the refund ledger is
empty, and the transform test checks that the tool was called with the
capped amount.
