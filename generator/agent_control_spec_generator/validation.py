# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validate generated artifacts with the engine that will run them.

Every check here goes through `agent_control_spec`, so the authority on a
generated artifact is the same runtime a host loads it into. The predecessor
generator shelled out to the `opa` executable and, when it was absent,
skipped Rego checking entirely behind a warning. The engine compiles Rego in
process, so there is no optional external validator and no skip path.

Three checks run, in increasing cost.

`validate_artifacts` compiles the manifest and the Rego together and reports
what activation would have surfaced.

`check_regex_patterns` compiles every redact pattern through the engine's own
regex engine. This one exists because an invalid pattern is otherwise
invisible: the manifest validates, the Rego compiles, and at evaluation the
builtin call goes undefined, the rule body fails, and the default `allow`
answers. A redaction rule that silently stops redacting is the worst failure
mode this generator can ship, so it is checked directly.

`smoke_evaluate` activates the policy and evaluates one synthetic agent-hooks
context per guarded point, asserting no `runtime_error:*` comes back. That
catches an unresolvable policy target, an undeclared annotator, and an
unprojectable tool, none of which the two static checks can see.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import yaml
from agent_control_spec import ActivatedPolicy
from agent_control_spec import validate_artifacts as _engine_validate
from agent_hooks import AgentContextBuilder

from .vocabulary import (
    POLICY_INPUT_ANNOTATIONS_KEY,
    POLICY_INPUT_POINT_KEY,
    REMOVED_INPUT_REFS,
    REMOVED_TRANSFORM_ROOT,
    manifest_version,
)

_REGEX_PROBE_PACKAGE = "acs_generator_regex_probe"


@dataclass
class ValidationResult:
    warnings: list[str] = field(default_factory=list)


class ValidationError(RuntimeError):
    """A generated artifact the engine rejects. The message is fed back to
    the model as a repair diagnostic."""


class _NullAnnotator:
    """Answers every annotator with an empty annotation.

    Smoke evaluation must not perform network input or output, and a declared
    `llm` or `endpoint` annotator would otherwise reach a bundled dispatcher
    that needs a credential and fail closed with
    `runtime_error:annotation_failed`, which says nothing about the generated
    artifact. An empty annotation still proves the binding resolves.
    """

    def dispatch(
        self,
        annotator_name: str,
        annotator: dict[str, Any],
        preliminary_policy_input: dict[str, Any],
    ) -> dict[str, Any]:
        return {}


def dump_manifest_yaml(manifest: dict[str, Any]) -> str:
    """Serialize a manifest document to YAML the engine parses."""
    return yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False)


def validate_artifacts(
    manifest: dict[str, Any],
    manifest_yaml: str,
    rego: str,
    slug: str,
    *,
    regex_patterns: tuple[str, ...] = (),
) -> ValidationResult:
    """Run every check against the generated pair. Raises `ValidationError`.

    `regex_patterns` are the redact patterns the policy will compile. The
    caller passes them because it built them, which is exact. Reading them
    back out of the rendered Rego would mean parsing nested builtin calls,
    and a redaction that chains two patterns renders one call inside
    another.
    """
    warnings: list[str] = []
    _reject_removed_refs(rego)
    _validate_with_engine(manifest_yaml, rego, slug)
    check_regex_patterns(tuple(dict.fromkeys(regex_patterns)))
    warnings.extend(smoke_evaluate(manifest, manifest_yaml, rego, slug))
    return ValidationResult(warnings)


def _bundles(rego: str, slug: str) -> dict[str, dict[str, Any]]:
    return {slug: {"modules": {f"{slug}.rego": rego}}}


def _validate_with_engine(manifest_yaml: str, rego: str, slug: str) -> None:
    diagnostics = _engine_validate(manifest_yaml, _bundles(rego, slug))
    if diagnostics:
        raise ValidationError(
            "engine rejected the generated artifacts: "
            + "; ".join(
                f"{item.get('code')}: {item.get('message')}" for item in diagnostics
            )
        )


def _reject_removed_refs(rego: str) -> None:
    """Refuse policy-input names the current contract removed.

    A removed name does not error. It evaluates to undefined, the rule body
    fails, and the default verdict answers, so the policy reads as written
    and enforces nothing.
    """
    found = sorted({ref for ref in REMOVED_INPUT_REFS if ref in rego})
    if found:
        raise ValidationError(
            "generated policy reads policy-input members the current contract "
            f"removed ({', '.join(found)}); the five members are "
            f"{POLICY_INPUT_POINT_KEY}, policy_target, snapshot, "
            f"{POLICY_INPUT_ANNOTATIONS_KEY} and tool"
        )
    if REMOVED_TRANSFORM_ROOT in rego:
        raise ValidationError(
            f"generated policy uses the removed {REMOVED_TRANSFORM_ROOT} transform "
            "root; AGENT-HOOKS-0.1 renamed it $target with no alias"
        )


def check_regex_patterns(patterns: tuple[str, ...]) -> None:
    """Compile each pattern through the engine's regex engine.

    Python's `re` is not consulted. It accepts lookaround and backreferences
    the engine rejects, and rejects Unicode class syntax such as `\\p{L}` the
    engine accepts, so it would both pass bad patterns and fail good ones.
    """
    if not patterns:
        return
    manifest = dump_manifest_yaml(
        {
            "agent_control_specification_version": manifest_version(),
            "metadata": {"name": _REGEX_PROBE_PACKAGE},
            "policies": {
                "probe": {
                    "type": "rego",
                    "bundle": "./policy",
                    "query": f"data.{_REGEX_PROBE_PACKAGE}.verdict",
                }
            },
            "intervention_points": {
                "input": {
                    "policy_target": "$.target",
                    "policy_target_kind": "user_input",
                    "policy": {
                        "id": "probe",
                        "query": f"data.{_REGEX_PROBE_PACKAGE}.verdict",
                    },
                }
            },
        }
    )
    # `regex.replace("", p, "")` is `""` for any pattern that compiles and is
    # undefined for any that does not, independent of what the pattern
    # matches. The index of each compiling pattern is collected, so one
    # evaluation reports on the whole set.
    module = (
        f"package {_REGEX_PROBE_PACKAGE}\n\n"
        "import rego.v1\n\n"
        f"patterns := {json.dumps(list(patterns))}\n\n"
        "compiles contains i if {\n"
        "\tsome i, p in patterns\n"
        '\tregex.replace("", p, "") == ""\n'
        "}\n\n"
        'verdict := {"decision": "allow", "reason": concat(",", '
        '[sprintf("%d", [i]) | some i in compiles])}\n'
    )
    policy = ActivatedPolicy.from_memory(
        manifest, {"probe": {"modules": {"probe.rego": module}}}
    )
    verdict = policy.evaluate(
        "input",
        AgentContextBuilder(
            agent_id="acs-generator", framework="acs-generator", session_id="probe"
        ).input(content=""),
    )
    reason = verdict.reason or ""
    if reason.startswith("runtime_error:"):
        raise ValidationError(
            f"could not check generated redact patterns against the engine: {reason}"
        )
    compiled = {int(index) for index in reason.split(",") if index}
    rejected = [pattern for i, pattern in enumerate(patterns) if i not in compiled]
    if rejected:
        raise ValidationError(
            "the engine's regex engine rejects these redact patterns, which would "
            "make the redaction rule silently stop redacting: "
            + ", ".join(repr(pattern) for pattern in rejected)
        )


def smoke_evaluate(
    manifest: dict[str, Any],
    manifest_yaml: str,
    rego: str,
    slug: str,
) -> list[str]:
    """Evaluate one synthetic context per guarded point. Returns warnings."""
    warnings: list[str] = []
    try:
        policy = ActivatedPolicy.from_memory(
            manifest_yaml,
            _bundles(rego, slug),
            annotator_dispatcher=_NullAnnotator(),
        )
    except Exception as exc:
        raise ValidationError(f"generated policy failed to activate: {exc}") from exc
    tool_names = sorted(manifest.get("tools", {}))
    builder = AgentContextBuilder(
        agent_id="acs-generator", framework="acs-generator", session_id="smoke"
    )
    evaluated = 0
    for point in manifest["intervention_points"]:
        contexts = _contexts_for(point, builder, tool_names)
        if not contexts:
            raise ValidationError(
                f"no smoke context could be built for guarded point '{point}', so it "
                "would be reported as evaluated without being evaluated"
            )
        for context in contexts:
            verdict = policy.evaluate(point, context)
            evaluated += 1
            reason = verdict.reason or ""
            if reason.startswith("runtime_error:"):
                raise ValidationError(
                    f"generated policy fails closed at '{point}' on a well-formed "
                    f"agent-hooks context with {reason}"
                )
    if evaluated < len(
        manifest["intervention_points"]
    ):  # pragma: no cover - guarded above
        raise ValidationError("smoke evaluation skipped a guarded intervention point")
    if not tool_names:
        guarded_tool_points = [
            point
            for point in manifest["intervention_points"]
            if point in ("pre_tool_call", "post_tool_call")
        ]
        if guarded_tool_points:
            warnings.append(
                "No tool is declared, so "
                + ", ".join(guarded_tool_points)
                + " is guarded without tool projection and input.tool is null in "
                "every evaluation. Supply a tool inventory to gate on tool identity."
            )
    return warnings


def _contexts_for(
    point: str, builder: AgentContextBuilder, tool_names: list[str]
) -> list[dict[str, Any]]:
    """Well-formed agent-hooks contexts for one point.

    Every declared tool gets its own context at a tool point, because tool
    projection is per call and an entry the catalog declares but cannot
    project would otherwise go unexercised. With no catalog the point is
    still exercised once with an arbitrary tool name, because the manifest
    then omits `tool_name_from` and nothing is projected. Skipping it would
    leave a guarded point unevaluated while the report claims otherwise.
    """
    text = "acs-generator smoke evaluation"
    names = tool_names or ["acs_generator_smoke_tool"]
    if point == "agent_startup":
        return [builder.agent_startup(tools_registered=list(tool_names))]
    if point == "input":
        return [builder.input(content=text)]
    if point == "pre_model_call":
        return [
            builder.pre_model_call(
                model_id="acs-generator-smoke",
                messages=[{"role": "user", "content": text}],
            )
        ]
    if point == "post_model_call":
        return [
            builder.post_model_call(
                model_id="acs-generator-smoke",
                content=text,
                tool_calls=[],
                finish_reason="stop",
            )
        ]
    if point == "pre_tool_call":
        return [
            builder.pre_tool_call(call_id=f"smoke-{name}", name=name, args={})
            for name in names
        ]
    if point == "post_tool_call":
        return [
            builder.post_tool_call(
                call_id=f"smoke-{name}", name=name, args={}, value=text
            )
            for name in names
        ]
    if point == "output":
        return [builder.output(content=text)]
    if point == "agent_shutdown":
        return [builder.agent_shutdown(reason="completed")]
    return []
