# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The closed vocabularies the generator is allowed to emit.

Every set here is pinned to the running engine rather than to a literal
where the engine exposes one. `agent_control_spec.supported_manifest_versions`
is the manifest grammar the installed runtime accepts, so an engine bump
moves the generated manifest with it instead of leaving a stale version
string that fails closed at load.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_control_spec import supported_manifest_versions

#: Annotator declaration types, ACS specification section 10.
ANNOTATOR_TYPES = frozenset({"classifier", "llm", "endpoint"})

#: Decisions a policy document may return, ACS specification section 13.
#: `allow`, `deny` and `transform` are the AGENT-HOOKS-0.1 verdicts. `warn`
#: and `escalate` are policy-language intents the runtime normalizes
#: natively to `allow` carrying `warnings[]` and to `deny` carrying an
#: `approval` block, so a plan may express them and the generated Rego may
#: emit them.
DECISIONS = frozenset({"allow", "warn", "deny", "escalate", "transform"})

#: Plan-level effect kinds that survive compilation to a section 14
#: transform. `append` is deliberately absent, see `plan._validate_effect`.
EFFECT_TYPES = frozenset({"replace", "redact"})

POLICY_BUNDLE = "./policy"
POLICY_TYPE = "rego"

#: Bounded LLM repair attempts. Each attempt is one provider call, so this
#: is also the per-generation call ceiling.
MAX_REPAIR_ATTEMPTS = 5

#: Top-level members of the policy input, ACS specification section 7. The
#: object has exactly five members, and generated Rego must read those
#: names. The pre-rename `stage` and `evidence` keys and the removed
#: `request`, `resource` and `tools` members silently evaluate to undefined
#: instead of failing, which reads as a passing policy.
POLICY_INPUT_POINT_KEY = "intervention_point"
POLICY_INPUT_ANNOTATIONS_KEY = "annotations"
REMOVED_INPUT_REFS = (
    "input.stage",
    "input.evidence",
    "input.request",
    "input.resource",
    "input.tools",
)

#: The `$policy_target` transform root of the predecessor tree. AGENT-HOOKS-0.1
#: renamed it `$target` with no alias, so a generated path that still uses the
#: old spelling fails closed at load.
REMOVED_TRANSFORM_ROOT = "$policy_target"


@dataclass(frozen=True)
class InterventionPointSpec:
    """One intervention point's generated manifest configuration."""

    name: str
    policy_target_kind: str
    tool_name_from: str | None = None


#: The value under evaluation at every intervention point.
#:
#: `target` is the AGENT-HOOKS-0.1 section 4 envelope member that carries the
#: value under control, so it is present at all eight points for any
#: conformant emitter and always holds exactly what a policy evaluates. The
#: predecessor generator instead named a per-point L1 member, which drifted:
#: `$.model_request` and `$.model_response` do not exist in an agent-hooks
#: context, so a manifest naming them fails closed with
#: `runtime_error:path_missing` at `pre_model_call` and `post_model_call`.
#: `$.target` also selects the tool result value rather than the
#: `{value, is_error}` wrapper at `post_tool_call`, which is the value a
#: transform there must replace.
POLICY_TARGET = "$.target"

INTERVENTION_POINTS = (
    InterventionPointSpec("agent_startup", "agent_metadata"),
    InterventionPointSpec("input", "user_input"),
    InterventionPointSpec("pre_model_call", "model_request"),
    InterventionPointSpec("post_model_call", "model_response"),
    InterventionPointSpec("pre_tool_call", "tool_args", "$.tool_call.name"),
    InterventionPointSpec("post_tool_call", "tool_result", "$.tool_call.name"),
    InterventionPointSpec("output", "assistant_output"),
    InterventionPointSpec("agent_shutdown", "shutdown_summary"),
)
INTERVENTION_POINT_NAMES = tuple(point.name for point in INTERVENTION_POINTS)
INTERVENTION_POINT_BY_NAME = {point.name: point for point in INTERVENTION_POINTS}

#: The JSON shape of `$target` at each point, as an AGENT-HOOKS-0.1 emitter
#: builds it. A policy reads these through `input.policy_target.value` and a
#: transform path indexes into them, so the model is given this table
#: verbatim in the system prompt.
TARGET_SHAPES = {
    "agent_startup": '{"tools_registered": [string]}',
    "input": '{"content": string, "role": string}',
    "pre_model_call": '[{"role": string, "content": string}, ...]',
    "post_model_call": '{"content": string, "tool_calls": [...], "finish_reason": string}',
    "pre_tool_call": "the tool arguments object, one member per argument",
    "post_tool_call": "the tool result value, any JSON type",
    "output": '{"content": string}',
    "agent_shutdown": '{"reason": string}',
}

#: Points at which `$target` may itself be a string. Everywhere else it is an
#: object or an array, so a redaction rooted at bare `$target` is guarded by
#: an `is_string` test that can never hold. The rule then never fires, the
#: default `allow` answers, and the redaction silently does nothing.
STRING_TARGET_POINTS = frozenset({"post_tool_call"})

#: Points at which AGENT-HOOKS-0.1 section 4.3 forbids a transform. A host
#: MUST reject one with `host_error:transform_target_forbidden`. The ACS
#: engine does not reject it, because the obligation is the host's, so a
#: generated transform rule at either point compiles and evaluates cleanly
#: and then fails at the host boundary on every firing.
TRANSFORM_FORBIDDEN_POINTS = frozenset({"agent_startup", "agent_shutdown"})

#: The member carrying redactable text at each point whose `$target` is an
#: object, used to name the right path in a repair diagnostic.
#: `agent_startup` and `agent_shutdown` are absent because no transform may
#: reach them, see `TRANSFORM_FORBIDDEN_POINTS`.
TEXT_MEMBER_BY_POINT = {
    "input": "$target.content",
    "post_model_call": "$target.content",
    "output": "$target.content",
}

#: The two points at which a tool is projected, ACS specification section 4.
#: `tool_name_from` is invalid anywhere else and fails closed.
TOOL_POINTS = frozenset(
    point.name for point in INTERVENTION_POINTS if point.tool_name_from
)


def manifest_version() -> str:
    """The manifest grammar version the installed engine accepts.

    Raises `RuntimeError` when the engine reports no supported version,
    because a generated manifest with no version cannot load.
    """
    versions = supported_manifest_versions()
    if not versions:
        raise RuntimeError(
            "the installed agent-control-spec engine reports no supported "
            "manifest version, so no manifest can be generated against it"
        )
    return versions[-1]
