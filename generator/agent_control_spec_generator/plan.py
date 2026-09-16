# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The constrained JSON policy plan a model is allowed to return.

The model never writes a manifest or a Rego module. It returns a plan, and
this module is the gate that plan passes through before anything is
compiled. Every rejection here is a rejection the engine would otherwise
make at load or, worse, would not make at all because the malformed
construct evaluates to undefined and reads as a passing policy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .vocabulary import (
    ANNOTATOR_TYPES,
    DECISIONS,
    EFFECT_TYPES,
    INTERVENTION_POINT_NAMES,
    REMOVED_TRANSFORM_ROOT,
    STRING_TARGET_POINTS,
    TARGET_SHAPES,
    TEXT_MEMBER_BY_POINT,
)


@dataclass(frozen=True)
class AnnotatorPlan:
    name: str
    type: str
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class AnnotationBindingPlan:
    point: str
    annotator: str
    from_path: str


@dataclass(frozen=True)
class RulePlan:
    point: str
    decision: str
    reason: str
    message: str
    conditions: tuple[str, ...] = ()
    effects: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class PolicyPlan:
    name: str
    guarded_points: tuple[str, ...]
    annotators: tuple[AnnotatorPlan, ...] = ()
    annotations: tuple[AnnotationBindingPlan, ...] = ()
    tools: tuple[str, ...] = ()
    rules: tuple[RulePlan, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)


class PlanError(ValueError):
    """A plan the generator refuses to compile. Carries the diagnostic the
    repair prompt feeds back to the model."""


def redact_patterns(plan: PolicyPlan) -> tuple[str, ...]:
    """Every redact regex that will reach the rendered policy.

    Only a `transform` rule carries effects into the Rego, and only a
    `redact` effect renders a regex, so nothing else needs checking. A
    `replace` effect's `pattern`, if the model supplied one, is ignored by
    the renderer and is therefore not a pattern the policy ever compiles.
    """
    return tuple(
        str(effect["pattern"])
        for rule in plan.rules
        if rule.decision == "transform"
        for effect in rule.effects
        if str(effect.get("type")) == "redact" and effect.get("pattern")
    )


def parse_policy_plan(raw: str) -> PolicyPlan:
    """Parse and validate one model response into a `PolicyPlan`."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PlanError(f"LLM response is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PlanError("LLM response must be a JSON object")
    return PolicyPlan(
        name=str(data.get("name") or data.get("metadata_name") or "generated_policy"),
        guarded_points=tuple(str(point) for point in _listed(data, "guarded_points")),
        annotators=tuple(_annotator(item) for item in _listed(data, "annotators")),
        annotations=tuple(_annotation(item) for item in _listed(data, "annotations")),
        tools=tuple(
            name
            for name in (_tool_name(tool) for tool in _listed(data, "tools"))
            if name
        ),
        rules=tuple(_rule(item) for item in _listed(data, "rules")),
        warnings=tuple(str(item) for item in _listed(data, "warnings")),
    )


def _listed(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise PlanError(f"'{key}' must be a JSON array")
    return value


def _tool_name(tool: Any) -> str:
    if isinstance(tool, dict):
        return str(tool.get("id") or tool.get("name") or "")
    return str(tool)


def _annotator(item: Any) -> AnnotatorPlan:
    if not isinstance(item, dict):
        raise PlanError("annotators entries must be objects")
    annotator_type = str(item.get("type", ""))
    if annotator_type not in ANNOTATOR_TYPES:
        raise PlanError(
            f"unsupported annotator type '{annotator_type}'; use one of: "
            + ", ".join(sorted(ANNOTATOR_TYPES))
        )
    labels = item.get("labels", [])
    if not isinstance(labels, list):
        raise PlanError("annotator labels must be a list")
    return AnnotatorPlan(
        name=str(item.get("name", "")),
        type=annotator_type,
        labels=tuple(str(label) for label in labels),
    )


def _annotation(item: Any) -> AnnotationBindingPlan:
    if not isinstance(item, dict):
        raise PlanError("annotations entries must be objects")
    return AnnotationBindingPlan(
        point=str(item.get("point", "")),
        annotator=str(item.get("annotator", "")),
        from_path=str(item.get("from", item.get("from_path", ""))),
    )


def _rule(item: Any) -> RulePlan:
    if not isinstance(item, dict):
        raise PlanError("rules entries must be objects")
    point = str(item.get("point", ""))
    if point not in INTERVENTION_POINT_NAMES:
        raise PlanError(
            f"unsupported rule point '{point}'; every rule must set point to one of: "
            + ", ".join(INTERVENTION_POINT_NAMES)
        )
    decision = str(item.get("decision", ""))
    if decision not in DECISIONS:
        raise PlanError(
            f"unsupported decision '{decision}'; use one of: "
            + ", ".join(sorted(DECISIONS))
        )
    effects = item.get("effects", [])
    if not isinstance(effects, list):
        raise PlanError("rule effects must be a list")
    if decision == "transform":
        _validate_transform_effects(effects, point)
    conditions = item.get("conditions", [])
    if not isinstance(conditions, list):
        raise PlanError("rule conditions must be a list")
    condition_tuple = tuple(
        str(condition) for condition in conditions if str(condition).strip()
    )
    if decision != "allow" and not condition_tuple:
        raise PlanError(
            f"rule for '{point}' with decision '{decision}' must define at least one "
            "condition; an unconditional rule would fire on every request at this "
            "intervention point"
        )
    return RulePlan(
        point=point,
        decision=decision,
        reason=_reason(item, decision),
        message=str(item.get("message", "")),
        conditions=condition_tuple,
        effects=tuple(effects),
    )


def _reason(item: dict[str, Any], decision: str) -> str:
    """The rule's reason, refusing the namespace the engine reserves.

    ACS specification section 13 requires that a policy reason MUST NOT
    start with `runtime_error:`. A policy that emits one fails closed with
    `runtime_error:policy_output_invalid`, so catching it here turns a
    runtime failure into a repair diagnostic.
    """
    reason = str(item.get("reason", decision))
    if reason.startswith("runtime_error:"):
        raise PlanError(
            f"rule reason '{reason}' uses the reserved runtime_error: namespace, which "
            "the engine rejects; choose a policy-owned reason string"
        )
    return reason


def _validate_transform_effects(effects: list[Any], point: str) -> None:
    for effect in effects:
        _validate_effect(effect, point)
    # ACS applies exactly one transform, one path and one value, per verdict
    # (specification section 14), so a transform rule whose effects target
    # different paths cannot be compiled faithfully. Require a single target
    # path and let the model author separate rules for separate locations.
    paths = {str(effect.get("path") or "$target") for effect in effects}
    if len(paths) > 1:
        raise PlanError(
            "a transform rule's effects must target a single path; got "
            + ", ".join(sorted(paths))
        )
    # A single verdict yields a single value, so a whole-value replace mixed
    # with a regex redact, or two replaces, cannot both be honored and would
    # compile to something the plan did not ask for.
    replaces = [e for e in effects if str(e.get("type")) == "replace"]
    redacts = [e for e in effects if str(e.get("type")) == "redact"]
    if replaces and redacts:
        raise PlanError(
            "a transform rule cannot mix replace and redact effects; use one or the other"
        )
    if len(replaces) > 1:
        raise PlanError("a transform rule may carry at most one replace effect")


def _validate_effect(effect: Any, point: str) -> None:
    if not isinstance(effect, dict):
        raise PlanError("effects must be objects")
    effect_type = str(effect.get("type", ""))
    if effect_type == "append":
        # `append` has no faithful single-target transform form. String
        # against array, and the path semantics differ, so it is rejected
        # rather than compiled into something that silently differs.
        raise PlanError(
            "append effect is not expressible as an ACS transform; use replace or redact"
        )
    if effect_type not in EFFECT_TYPES:
        raise PlanError(
            f"unsupported effect type '{effect_type}'; use one of: "
            + ", ".join(sorted(EFFECT_TYPES))
        )
    path = str(effect.get("path", ""))
    if path.startswith(REMOVED_TRANSFORM_ROOT):
        raise PlanError(
            f"effect path '{path}' uses the removed {REMOVED_TRANSFORM_ROOT} root; "
            "AGENT-HOOKS-0.1 renamed it $target with no alias"
        )
    if not path.startswith("$target"):
        raise PlanError(f"effect path must start with $target: {path}")
    if effect_type == "redact":
        pattern = effect.get("pattern")
        if not pattern:
            raise PlanError("redact effect requires a 'pattern'")
        if not isinstance(pattern, str):
            raise PlanError("redact effect 'pattern' must be a string")
        _reject_unreachable_redact(path, point)
        # Regex validity is checked against the engine's own regex engine in
        # `validation.check_regex_patterns`. Python's `re` is deliberately not
        # used: it accepts patterns the engine rejects (lookaround, backrefs)
        # and rejects patterns the engine accepts (\p{L}), so it is the wrong
        # authority on either side.
    if effect_type == "replace" and "value" not in effect:
        raise PlanError("replace effect requires a 'value'")


def _reject_unreachable_redact(path: str, point: str) -> None:
    """Refuse a redaction rooted where `$target` is never a string.

    A regex redaction compiles to a rule body guarded by `is_string` on the
    value at the path. At every point but `post_tool_call` the bare `$target`
    is an object or an array, so that guard never holds, the rule never
    fires, and the default `allow` answers. The redaction reads as authored
    and removes nothing, which is the one failure the generator must not
    ship quietly.
    """
    if path != "$target" or point in STRING_TARGET_POINTS:
        return
    suggestion = TEXT_MEMBER_BY_POINT.get(point)
    detail = (
        f" Redact the text member instead, which at '{point}' is {suggestion}."
        if suggestion
        else f" At '{point}' the target is {TARGET_SHAPES.get(point, 'not a string')},"
        " so name the member holding the text."
    )
    raise PlanError(
        f"a redact effect at '{point}' targets bare $target, which is "
        f"{TARGET_SHAPES.get(point, 'not a string')} and never a string, so the "
        "rule can never fire and the redaction would silently do nothing." + detail
    )
