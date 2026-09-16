# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compile a validated plan into one Rego module.

One entrypoint per guarded intervention point, plus a dispatching `verdict`
rule, matching the queries `manifest_builder` binds. Rules at the same point
are emitted as a single else-chain so the engine never sees two complete
rules producing conflicting values for one entrypoint.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from .plan import PolicyPlan, RulePlan
from .vocabulary import INTERVENTION_POINT_NAMES, POLICY_INPUT_POINT_KEY

INDENT = "    "

# The section 14 transform path grammar as the engine enforces it: `$target`
# followed by zero or more `.field` or `[N]` segments. The engine rejects a
# quoted bracket key and a trailing empty segment, so anything outside this
# shape is reset to the root rather than compiled into a load failure.
_TRANSFORM_PATH_RE = re.compile(r"^\$target(\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*$")

# Higher wins when more than one rule body matches at the same point.
# `transform` outranks `warn` so a redaction is never shadowed by an advisory
# rule, and stays below `escalate` and `deny`, which stop the action.
_DECISION_SEVERITY = {"deny": 4, "escalate": 3, "transform": 2, "warn": 1, "allow": 0}


def build_rego(plan: PolicyPlan, slug: str) -> str:
    rules_by_point: dict[str, list[RulePlan]] = defaultdict(list)
    for rule in plan.rules:
        rules_by_point[rule.point].append(rule)
    lines = [
        f"package agent_control_specification.{slug}",
        "",
        "import rego.v1",
        "",
        'default verdict := {"decision": "allow"}',
    ]
    lines.extend(
        f'default {point}_verdict := {{"decision": "allow"}}'
        for point in INTERVENTION_POINT_NAMES
    )
    lines.append("")
    lines.extend(
        f'verdict := {point}_verdict if {{ input.{POLICY_INPUT_POINT_KEY} == "{point}" }}'
        for point in INTERVENTION_POINT_NAMES
    )
    for point in INTERVENTION_POINT_NAMES:
        rules = rules_by_point.get(point)
        if rules:
            lines.extend(["", *_render_point(point, rules)])
    lines.append("")
    return "\n".join(lines)


def _render_point(point: str, rules: list[RulePlan]) -> list[str]:
    ordered = sorted(rules, key=lambda rule: -_DECISION_SEVERITY.get(rule.decision, 0))
    lines: list[str] = []
    for index, rule in enumerate(ordered):
        verdict_str, extra_body = _render_verdict(rule)
        head = (
            f"{point}_verdict := {verdict_str}"
            if index == 0
            else f"else := {verdict_str}"
        )
        lines.append(f"{head} if {{")
        lines.append(f'{INDENT}input.{POLICY_INPUT_POINT_KEY} == "{point}"')
        for condition in rule.conditions:
            for line in condition.splitlines():
                if line.strip():
                    lines.append(f"{INDENT}{line.strip()}")
        for line in extra_body:
            lines.append(f"{INDENT}{line}")
        lines.append("}")
    return lines


def _verdict_fields(rule: RulePlan) -> dict[str, Any]:
    verdict: dict[str, Any] = {"decision": rule.decision, "reason": rule.reason}
    if rule.message:
        verdict["message"] = rule.message
    return verdict


def _render_verdict(rule: RulePlan) -> tuple[str, list[str]]:
    """The verdict object plus any extra body lines it needs.

    Only a `transform` decision may carry a value-changing payload, and it is
    a single `{path, value}` object rooted at `$target`. `allow`, `warn`,
    `deny` and `escalate` never mutate, so their effects are dropped and
    surfaced as a generation warning by the engine module.
    """
    verdict = _verdict_fields(rule)
    if rule.decision != "transform":
        return json.dumps(verdict, indent=4), []
    return _render_transform_verdict(verdict, rule)


def _redaction_replacement(effect: dict[str, Any]) -> str:
    # An explicit empty string is a deletion-style redaction, so test for
    # None rather than truthiness.
    replacement = "[REDACTED]"
    for key in ("value", "replacement"):
        if effect.get(key) is not None:
            replacement = str(effect[key])
            break
    # `regex.replace` expands `$1` and `$name` in the replacement as capture
    # group references, which could re-insert the text just redacted. The
    # replacement is literal text, so `$` is escaped.
    return replacement.replace("$", "$$")


def _read_expr_for_path(path: str) -> str:
    """The Rego read expression for a `$target` transform path.

    `$target` is the policy input's `policy_target.value`, so `$target.text`
    reads `input.policy_target.value.text` and `$target[0]` reads
    `input.policy_target.value[0]`.
    """
    return "input.policy_target.value" + path[len("$target") :]


def _render_transform_verdict(
    verdict: dict[str, Any], rule: RulePlan
) -> tuple[str, list[str]]:
    # Route on effect type, not on the presence of a `pattern` field: a
    # `replace` carrying a stray pattern is still a whole-value replacement.
    redacts = [e for e in rule.effects if str(e.get("type")) == "redact"]
    if redacts:
        # Chain `regex.replace` over this rule's own patterns only. Patterns
        # are deliberately not unioned across sibling rules, because another
        # rule's redaction is gated by that rule's conditions and applying it
        # here would redact content this rule was not authorized to touch.
        path = _normalize_transform_path(str(redacts[0].get("path") or "$target"))
        read_expr = _read_expr_for_path(path)
        extra_body = [f"is_string({read_expr})"]
        expr = read_expr
        for effect in redacts:
            replacement = _redaction_replacement(effect)
            expr = (
                f"regex.replace({expr}, {json.dumps(str(effect['pattern']))}, "
                f"{json.dumps(replacement)})"
            )
        extra_body.append(f"__transform_value := {expr}")
        return _verdict_with_value_ref(verdict, path, "__transform_value"), extra_body
    effect = rule.effects[0] if rule.effects else {}
    path = _normalize_transform_path(str(effect.get("path") or "$target"))
    if "value" in effect:
        verdict["transform"] = {"path": path, "value": effect["value"]}
        return json.dumps(verdict, indent=4), []
    # A transform decision with no usable effect. Replacing the target with
    # itself keeps the verdict valid, where omitting `transform` would fail
    # closed with `runtime_error:policy_output_invalid`.
    extra_body = [f"__transform_value := {_read_expr_for_path(path)}"]
    return _verdict_with_value_ref(verdict, path, "__transform_value"), extra_body


def _normalize_transform_path(path: str) -> str:
    # Models routinely append `.value`, conflating the transform root with
    # the `input.policy_target.value` read path. The policy target is the
    # value, so `$target.value` indexes into it and the engine rejects that
    # on a scalar target. Deeper paths are left intact.
    if path == "$target.value":
        return "$target"
    # Anything outside the grammar is reset to the root so the engine never
    # fails closed on a malformed path.
    if not _TRANSFORM_PATH_RE.match(path):
        return "$target"
    return path


def _verdict_with_value_ref(verdict: dict[str, Any], path: str, value_ref: str) -> str:
    """The verdict object with an unquoted Rego variable as `transform.value`."""
    fields = ", ".join(
        f"{json.dumps(key)}: {json.dumps(value)}" for key, value in verdict.items()
    )
    transform = f'"transform": {{"path": {json.dumps(path)}, "value": {value_ref}}}'
    return "{" + fields + ", " + transform + "}"
