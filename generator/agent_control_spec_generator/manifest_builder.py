# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compile a validated plan into an ACS manifest document.

The manifest is derived from what the rules actually reference, not only
from what the plan declared. A rule that reads `input.annotations.pii` but
whose plan forgot to bind that annotator would compile to a policy that can
never fire, because `input.annotations.pii` is then always empty. That is a
silent fail-open, so the bindings are recovered from the rule bodies.
"""

from __future__ import annotations

import re
from typing import Any

from .plan import PolicyPlan
from .util import slugify
from .vocabulary import (
    INTERVENTION_POINT_BY_NAME,
    POLICY_BUNDLE,
    POLICY_TARGET,
    POLICY_TYPE,
    manifest_version,
)

# A Rego string literal, double-quoted or raw-backticked. `_STR` captures the
# content of either form through two alternative groups, one of which is None.
_DQ = r'"([^"]+)"'
_BT = r"`([^`]+)`"
_STR = rf"(?:{_DQ}|{_BT})"
# A tool name or id read, in dot or bracket form.
_TOOL_FIELD = (
    r"""input\.tool(?:\.(?:name|id)|\[\s*(?:"(?:name|id)"|`(?:name|id)`)\s*\])"""
)
_TOOL_NAME_CONDITION = re.compile(rf"{_TOOL_FIELD}\s*==\s*{_STR}")
# The same comparison with the operands the other way round, which a model
# writes about as often. Missing it leaves the tool out of the catalog, so
# `input.tool` stays null and the rule gating on it can never fire.
_TOOL_NAME_CONDITION_REVERSED = re.compile(rf"{_STR}\s*==\s*{_TOOL_FIELD}")
# The generator's own tool-id idiom, object.get(input.tool, "id",
# object.get(input.tool, "name", "")) == "wire_transfer".
_TOOL_GET_CONDITION = re.compile(rf"object\.get\(\s*input\.tool\b[^=]*==\s*{_STR}")
# A set or array membership gate, input.tool.id in {"a", "b"}.
_TOOL_IN_CONDITION = re.compile(
    rf"(?:{_TOOL_FIELD}|object\.get\(\s*input\.tool\b[^{{\[]*?)\s+in\s+[\{{\[]([^}}\]]*)[\}}\]]"
)
_SET_STRING = re.compile(_STR)
# `annotations` reached by dot or by bracket, then the annotator name by
# either form again.
_ANNOTATIONS_ROOT = (
    r"""input(?:\.annotations|\[\s*(?:"annotations"|`annotations`)\s*\])"""
)
_ANNOTATION_REF = re.compile(
    rf"{_ANNOTATIONS_ROOT}(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*{_STR}\s*\])"
)
_ANNOTATION_GET = re.compile(rf"object\.get\(\s*{_ANNOTATIONS_ROOT}\s*,\s*{_STR}")


def _match_string(match: re.Match[str], first_group: int) -> str:
    """Whichever of the two alternative string-literal groups matched."""
    if match.group(first_group) is not None:
        return match.group(first_group)
    return match.group(first_group + 1)


def _annotation_names(text: str) -> set[str]:
    names: set[str] = set()
    for match in _ANNOTATION_REF.finditer(text):
        if match.group(1) is not None:
            names.add(match.group(1))
        else:
            names.add(_match_string(match, 2))
    for match in _ANNOTATION_GET.finditer(text):
        names.add(_match_string(match, 1))
    return names


def referenced_annotators_by_point(plan: PolicyPlan) -> dict[str, set[str]]:
    """Annotators each point's rules actually read, keyed by point."""
    by_point: dict[str, set[str]] = {}
    for rule in plan.rules:
        names = _annotation_names(" ".join(rule.conditions))
        if names:
            by_point.setdefault(rule.point, set()).update(names)
    return by_point


def referenced_tool_names(plan: PolicyPlan) -> list[str]:
    """Tools the plan lists plus every tool name a rule gates on.

    A tool intervention point requires every projected tool to be present in
    the catalog. A name the rules gate on but the catalog omits fails closed
    with `runtime_error:tool_unknown` on the first call that uses it.
    """
    names: dict[str, None] = {name: None for name in plan.tools if name}
    for rule in plan.rules:
        for condition in rule.conditions:
            for pattern in (_TOOL_NAME_CONDITION, _TOOL_GET_CONDITION):
                for match in pattern.finditer(condition):
                    names.setdefault(_match_string(match, 1), None)
            for match in _TOOL_NAME_CONDITION_REVERSED.finditer(condition):
                names.setdefault(_match_string(match, 1), None)
            for match in _TOOL_IN_CONDITION.finditer(condition):
                for literal in _SET_STRING.finditer(match.group(1)):
                    names.setdefault(_match_string(literal, 1), None)
    return sorted(names)


def build_tool_catalog(
    plan: PolicyPlan, tool_inventory: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """The manifest tool catalog.

    Every tool the caller supplied is carried, not only the ones a rule
    mentions. A supplied tool left out of the catalog fails closed with
    `runtime_error:tool_unknown` on every call to it, so dropping the
    unreferenced ones would brick the rest of the agent's tools the moment a
    tool point is guarded.

    Each entry gets `id` and `name` when it lacks them, because the generated
    rules gate on `input.tool.id` and fall back to `input.tool.name`, and an
    entry carrying neither leaves both undefined.
    """
    catalog: dict[str, dict[str, Any]] = {}
    for name in sorted({*tool_inventory, *referenced_tool_names(plan)}):
        entry = dict(tool_inventory.get(name) or {})
        entry.setdefault("type", "Tool")
        entry.setdefault("id", name)
        entry.setdefault("name", name)
        catalog[name] = entry
    return catalog


def build_manifest(
    plan: PolicyPlan, tool_inventory: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], str]:
    """Return the manifest document and the slug naming its policy."""
    slug = slugify(plan.name)
    policy_id = slug
    annotators_by_point = referenced_annotators_by_point(plan)
    tools = build_tool_catalog(plan, tool_inventory)
    manifest: dict[str, Any] = {
        "agent_control_specification_version": manifest_version(),
        "metadata": {"name": slug},
        "policies": {
            policy_id: {
                "type": POLICY_TYPE,
                "bundle": POLICY_BUNDLE,
                "query": f"data.agent_control_specification.{slug}.verdict",
            }
        },
        "intervention_points": {},
    }
    for point_name in _guarded_points(plan):
        spec = INTERVENTION_POINT_BY_NAME[point_name]
        config: dict[str, Any] = {
            "policy_target": POLICY_TARGET,
            "policy_target_kind": spec.policy_target_kind,
            "policy": {
                "id": policy_id,
                "query": f"data.agent_control_specification.{slug}.{point_name}_verdict",
            },
        }
        # `tool_name_from` projects the named tool out of the catalog, and a
        # name the catalog does not carry fails closed with
        # `runtime_error:tool_unknown`. With no catalog at all that is every
        # tool call, which turns "guard tool arguments" into "deny every tool
        # call", so the field is emitted only when there is a catalog to
        # project from.
        if spec.tool_name_from and tools:
            config["tool_name_from"] = spec.tool_name_from
        annotations = {
            binding.annotator: {"from": binding.from_path or "$target"}
            for binding in plan.annotations
            if binding.point == point_name and binding.annotator
        }
        for name in sorted(annotators_by_point.get(point_name, set())):
            annotations.setdefault(name, {"from": "$target"})
        if annotations:
            config["annotations"] = annotations
        manifest["intervention_points"][point_name] = config
    referenced = {name for names in annotators_by_point.values() for name in names}
    declared = {a.name: a.type for a in plan.annotators if a.name}
    annotators = {
        name: {"type": declared.get(name, "classifier")}
        for name in sorted(set(declared) | referenced)
    }
    if annotators:
        manifest["annotators"] = annotators
    if tools:
        manifest["tools"] = tools
    return manifest, slug


def _guarded_points(plan: PolicyPlan) -> list[str]:
    """Declared guarded points plus every point a rule targets.

    A rule whose point the manifest does not guard is emitted into the Rego
    and never queried, so the rule reads as written and enforces nothing.
    Declared order is preserved and the extras are appended. An unknown name
    is dropped here because `plan._rule` already rejects one on a rule, so
    the only way to reach this is a stray `guarded_points` entry.
    """
    guarded = [
        point
        for point in dict.fromkeys(plan.guarded_points)
        if point in INTERVENTION_POINT_BY_NAME
    ]
    for rule in plan.rules:
        if rule.point not in guarded:
            guarded.append(rule.point)
    return guarded
