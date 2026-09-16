# ACS policy generator

Describe an agent in prose and get an ACS manifest and a Rego policy back.

The caller supplies a system prompt, a plain description of the agent, a
statement of the policy, or any mixture of the three. A language model turns
that into a constrained policy plan. The generator compiles the plan into
artifacts and validates them with `agent_control_spec`, the engine that will
evaluate them at runtime. Nothing is written until validation passes.

## The output is a draft

A model wrote the rules. The engine checked that they load, compile, and
return a verdict rather than a fail closed error. No check here establishes
that the policy says what the prose asked for, or that a regular expression
matches the text a reviewer had in mind, or that a guardrail the prose
implied but never stated made it into a rule at all. Read `report.md`, then
read every rule, before binding the policy to an agent.

## Install

```bash
pip install ./generator
```

The engine comes with it. `agent-control-spec` is a dependency, so the
validator and the runtime the artifacts target are the same build.

## Generate

```bash
export ACS_GENERATOR_API_KEY="..."

acs-policy-gen \
  --prompt "Retail banking assistant. Block passwords in prompts, require a
            human to approve wire transfers above 10000, and mask account
            numbers in the final answer." \
  --tool wire_transfer:banking,payments \
  --out build/payments
```

That writes three files.

| Path | Contents |
| --- | --- |
| `manifest.yaml` | The ACS manifest, naming the guarded intervention points, the tool catalog, the annotators, and the bound policy |
| `policy/<slug>.rego` | One Rego module with an entrypoint per guarded point |
| `report.md` | What was assumed, what the engine checked, and what no check established |

Add `--dry-run` to print the artifacts instead of writing them. The output
directory must be empty, including on a second run over an earlier one. Pass
`--force` to replace what is there.

## Inputs

| Input | How it is supplied |
| --- | --- |
| Guardrail prose | `--prompt`, or `--prompt-file FILE`, or `--prompt-file -` to read stdin |
| Tool inventory | `--tool NAME:LABEL,LABEL`, repeatable, and `--tools-file FILE` holding a JSON or YAML mapping of tool name to catalog entry |
| Output directory | `--out DIR` |

A tool the policy gates on should appear in the inventory. Every tool you
supply reaches the manifest catalog, whether or not a rule mentions it,
because a tool missing from the catalog fails closed with
`runtime_error:tool_unknown` on every call to it. Keeping only the referenced
ones would brick the rest of the agent's tools the moment a tool point is
guarded. A name that only a rule mentions is recovered and added with minimal
metadata, and that is reported as a warning.

## Configuration

Every provider setting has a flag and an environment variable. The
environment variable is the better place for the key, which keeps it out of
shell history and out of process listings.

| Flag | Variable | Default | Meaning |
| --- | --- | --- | --- |
| `--api-key` | `ACS_GENERATOR_API_KEY` | none | Provider credential. Required |
| `--api-base` | `ACS_GENERATOR_API_BASE` | `https://api.openai.com/v1` | Chat completions base URL |
| `--model` | `ACS_GENERATOR_MODEL` | `gpt-4o-mini` | Model or Azure deployment name |
| `--api-version` | `ACS_GENERATOR_API_VERSION` | none | Azure OpenAI api-version. Setting it selects Azure `api-key` auth |
| `--max-attempts` | none | 5 | Model calls per generation, one per repair round |

Azure mode is also selected by an `*.azure.com` API base. It changes the
auth header and appends the api-version query string.

A key is read only when a generation runs. Importing the package contacts
nothing and reads no credential, so a test suite or a CI job can import it
freely.

### Call budget

One generation costs between one and `--max-attempts` model calls. The first
call produces a plan. Each rejection sends the engine's own diagnostic back
for repair, and every attempt failing raises an error and writes nothing.

## What the generator checks

Validation runs against the engine, not against a copy of its rules.

- The manifest validates under the engine's manifest grammar, at the version
  the installed engine reports rather than a version pinned here.
- The Rego module compiles under the engine that will evaluate it. Rego is
  compiled in process, so there is no external validator to install and no
  path that silently skips this.
- Every redact pattern, and every regular expression a rule condition passes
  to a Rego builtin, compiles under the engine's own regular expression
  engine. These catch a failure that is otherwise invisible. An invalid
  pattern leaves the manifest valid and the module compiling, and at
  evaluation the builtin call goes undefined, the rule body fails, and the
  default `allow` answers. The rule reads exactly as authored and does
  nothing.
- Every guarded intervention point is evaluated against a well formed
  agent-hooks context and must return a policy verdict rather than a
  `runtime_error:*` fail closed deny. That catches an unresolvable policy
  target, an annotator bound to nothing, and a tool the catalog cannot
  project.

The plan gate refuses several shapes before compilation, each because the
engine would otherwise accept the artifact and enforce less than it appears
to.

| Refused | Why |
| --- | --- |
| A rule with no condition, or gated only by a tautology such as `true` | It fires on every request at its point |
| A reason in the reserved `runtime_error:` namespace | The engine rejects it at evaluation |
| A redaction rooted at bare `$target` where the target is an object | The `is_string` guard never holds, so the rule never fires |
| A transform carrying no effect | It would replace the value with itself and report a rewrite |
| Two transform rules at one point | Rules at a point are one else-chain, so only the first match runs |
| A transform path naming a member the target does not have | Resolving the path is a host obligation, so it fails at the host, not here |
| `$target.value` | The policy target already is the value |
| A transform at `agent_startup` or `agent_shutdown` | Forbidden by AGENT-HOOKS-0.1 section 4.3, and the engine will not catch it, because rejecting it is the host's obligation |

Where the predecessor silently repaired a path it did not recognize by
resetting it to the root, this rejects instead, which turns a typo into a
repair round rather than into a whole-value replacement.

## Python API

```python
from pathlib import Path

from agent_control_spec_generator import GenerationEngine
from agent_control_spec_generator.llm import OpenAICompatibleLanguageModel

result = GenerationEngine(OpenAICompatibleLanguageModel()).generate(
    prompt=Path("guardrails.md").read_text(encoding="utf-8"),
    out_dir=Path("build/payments"),
    tool_inventory={"wire_transfer": {"type": "Tool", "clearance": "confidential"}},
)

print(result.slug, result.attempts, result.warnings)
```

`generate` returns the slug, the manifest as both a dict and YAML, the Rego
source, the report, the warnings, and the number of model calls it took.
Pass `write=False` to get the artifacts without touching disk.

Any object with a `complete(system, user) -> str` method is a model, so an
internal deployment or a recorded transcript substitutes for the bundled
provider. `StubLanguageModel` is the scripted one the tests and the example
use.

## Example

`examples/payments_agent.py` generates a payments policy from prose and then
enforces it, evaluating real agent-hooks contexts through
`agent_control_spec`. It contacts nothing, because the model is scripted.

```bash
python examples/payments_agent.py
```

It prints each verdict the policy produces. A password in the prompt is
denied. A large transfer comes back as a deny carrying an approval block,
which is how an escalation is expressed. Output naming an account number
comes back as a transform carrying the redacted text. Everything else is
allowed.

## How generated verdicts behave

The generated policy may express five decisions, and the runtime normalizes
two of them. A `warn` becomes an `allow` carrying the reason and message in
`warnings[]`. An `escalate` becomes a `deny` carrying an `approval` block,
which the host lifts through its approval seam. `allow`, `deny`, and
`transform` pass through.

The runtime computes verdicts and does not act on them. Applying a
transform, honouring `evaluate_only`, and resolving an approval are host
obligations under AGENT-HOOKS-0.1.

## Tests

```bash
pip install ./generator pytest
pytest generator
```

The suite is deterministic and offline. Every model is scripted, and the
assertions about behavior are made by loading the generated artifacts into
`agent_control_spec` and evaluating them.
