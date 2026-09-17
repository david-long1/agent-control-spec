# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Inspect condition bodies with OPA's parser before the runtime sees them.

The original AGT generator also used OPA for authoring checks. OPA is only a
parser here; generated policies are compiled and evaluated by ACS.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


class ConditionError(ValueError):
    """A condition cannot be checked within the supported authoring subset."""


def require_opa() -> str:
    path = shutil.which("opa")
    if path is None:
        raise RuntimeError(
            "OPA is required for generation; install opa and put it on PATH"
        )
    return path


@lru_cache(maxsize=128)
def _parse(body: str) -> dict[str, Any]:
    source = (
        f"package acs_generator_conditions\nimport rego.v1\ncheck if {{\n{body}\n}}\n"
    )
    try:
        with tempfile.TemporaryDirectory(prefix="acs-conditions-") as directory:
            path = Path(directory) / "conditions.rego"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [require_opa(), "parse", "--format=json", str(path)],
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=10,
                check=False,
            )
    except subprocess.TimeoutExpired:
        raise ConditionError("condition parsing timed out") from None
    if result.returncode:
        raise ConditionError("invalid Rego conditions: " + result.stderr[:2000])
    document = json.loads(result.stdout)
    rules = document.get("rules", [])
    if (
        document.get("package", {}).get("path")
        != [
            {"type": "var", "value": "data"},
            {"type": "string", "value": "acs_generator_conditions"},
        ]
        or document.get("imports")
        != [
            {
                "path": {
                    "type": "ref",
                    "value": [
                        {"type": "var", "value": "rego"},
                        {"type": "string", "value": "v1"},
                    ],
                },
            }
        ]
        or len(rules) != 1
        or rules[0].get("head", {}).get("name") != "check"
        or "else" in rules[0]
        or rules[0]["head"].get("value") != {"type": "boolean", "value": True}
    ):
        raise ConditionError("conditions must be a rule body, not additional rules")
    return rules[0]


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _ref(term: dict[str, Any]) -> tuple[Any, ...]:
    if term.get("type") == "var":
        return (term["value"],)
    if term.get("type") != "ref":
        return ()
    return tuple(
        part["value"]
        if part.get("type") in {"string", "number"}
        or index == 0
        and part.get("type") == "var"
        else None
        for index, part in enumerate(term["value"])
    )


def _calls(node: Any) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    for entry in _walk(node):
        terms = entry.get("terms")
        if entry.get("type") == "call":
            terms = entry["value"]
        if isinstance(terms, list) and terms:
            ref = _ref(terms[0])
            if not ref or not all(isinstance(part, str) for part in ref):
                raise ConditionError("dynamic function calls are not supported")
            yield ".".join(ref), terms[1:]


@dataclass(frozen=True)
class ConditionInfo:
    patterns: tuple[str, ...]
    annotators: frozenset[str]
    tools: frozenset[str]
    uses_tool: bool


# Keep authoring evaluation free of network, host/environment introspection,
# clocks, random values and diagnostic output. Unknown functions require review.
_CALLS = frozenset(
    [
        "assign",
        "eq",
        "equal",
        "neq",
        "gt",
        "gte",
        "lt",
        "lte",
        "plus",
        "minus",
        "mul",
        "div",
        "rem",
        "and",
        "or",
        "xor",
        "internal.member_2",
        "internal.member_3",
        "contains",
        "startswith",
        "endswith",
        "lower",
        "upper",
        "trim",
        "trim_space",
        "trim_prefix",
        "trim_suffix",
        "split",
        "concat",
        "substring",
        "replace",
        "sprintf",
        "count",
        "sum",
        "max",
        "min",
        "sort",
        "is_string",
        "is_number",
        "is_boolean",
        "is_array",
        "is_object",
        "is_set",
        "is_null",
        "object.get",
        "object.keys",
        "object.values",
        "object.union",
        "object.remove",
        "object.filter",
        "array.concat",
        "array.slice",
        "array.reverse",
        "regex.match",
        "regex.replace",
        "regex.split",
        "regex.find_n",
        "regex.find_all_string_submatch_n",
        "regex.is_valid",
        "to_number",
        "to_string",
        "json.marshal",
        "json.unmarshal",
    ]
)
_REGEX_ARGS = {
    "regex.match": 0,
    "regex.split": 0,
    "regex.find_n": 0,
    "regex.find_all_string_submatch_n": 0,
    "regex.replace": 1,
}
_ROOTS = {"intervention_point", "policy_target", "snapshot", "annotations", "tool"}
_OBJECT_MEMBERS = {
    "agent_startup": {"tools_registered"},
    "input": {"content", "role"},
    "post_model_call": {"content", "tool_calls", "finish_reason"},
    "output": {"content"},
    "agent_shutdown": {"reason"},
}


def inspect_conditions(conditions: tuple[str, ...], point: str) -> ConditionInfo:
    if not conditions:
        return ConditionInfo((), frozenset(), frozenset(), False)
    tree = _parse("\n".join(conditions))
    nodes = list(_walk(tree))
    # Literal/alias inference below is single-scope. Flattening bindings from
    # comprehensions or every blocks would let a local literal certify an
    # unrelated request-controlled variable with the same name.
    if any(
        node.get("type")
        in {
            "arraycomprehension",
            "setcomprehension",
            "objectcomprehension",
        }
        or "domain" in node
        for node in nodes
    ):
        raise ConditionError(
            "nested condition scopes are not supported; use top-level some statements "
            "instead of comprehensions or every blocks"
        )
    calls = list(_calls(tree))
    if any(
        _ref(expr.get("terms", {})) == ("input",)
        for expr in tree["body"]
        if isinstance(expr.get("terms"), dict)
    ):
        raise ConditionError(
            "bare input selects every request; use a request-specific condition"
        )
    if any("with" in node for node in nodes):
        raise ConditionError(
            "conditions must not replace input or builtins with 'with'"
        )
    for name, _ in calls:
        if name not in _CALLS:
            raise ConditionError(f"unsupported condition function '{name}'")

    bindings: dict[str, list[dict[str, Any]]] = {}
    for name, args in calls:
        if name in {"assign", "eq"} and len(args) == 2:
            left, right = args
            if left.get("type") == "var":
                bindings.setdefault(left["value"], []).append(right)
            if name == "eq" and right.get("type") == "var":
                bindings.setdefault(right["value"], []).append(left)
        if (
            name == "internal.member_2"
            and len(args) >= 2
            and args[0].get("type") == "var"
            and args[1].get("type") in {"array", "set"}
        ):
            bindings.setdefault(args[0]["value"], []).extend(args[1]["value"])

    def literals(term: dict[str, Any], seen: tuple[str, ...] = ()) -> list[str]:
        if term.get("type") == "string":
            return [term["value"]]
        ref = _ref(term)
        if len(ref) == 1 and ref[0] in bindings and ref[0] not in seen:
            values = [literals(value, (*seen, ref[0])) for value in bindings[ref[0]]]
            if values and all(values):
                return [literal for value in values for literal in value]
        return []

    def resolved(term: dict[str, Any], seen: tuple[str, ...] = ()) -> tuple[Any, ...]:
        ref = _ref(term)
        if not ref:
            return ()
        if ref[0] in bindings and ref[0] not in seen:
            candidates = {
                resolved(value, (*seen, ref[0])) for value in bindings[ref[0]]
            }
            candidates.discard(())
            if len(candidates) > 1:
                raise ConditionError(
                    "ambiguous input aliases; use direct input references"
                )
            if candidates:
                return (*next(iter(candidates)), *ref[1:])
        return ref

    patterns: list[str] = []
    annotators: set[str] = set()
    tools: set[str] = set()
    references = [resolved(node) for node in nodes if node.get("type") == "ref"]
    # object.get is also an input read; resolve its literal key before checking
    # the five-member policy input and discovering annotation dependencies.
    for name, args in calls:
        if name == "object.get" and len(args) == 3:
            root = resolved(args[0])
            keys = literals(args[1])
            if root and root[0] == "input":
                if root in {("input",), ("input", "annotations")} and not keys:
                    raise ConditionError(
                        "object.get needs a literal key at the input/annotation root"
                    )
                references.extend((*root, key) for key in keys)
        if name in _REGEX_ARGS:
            index = _REGEX_ARGS[name]
            values = literals(args[index]) if len(args) > index else []
            if not values:
                raise ConditionError(
                    "regex patterns must be literals or variables bound to literal strings; "
                    "computed patterns cannot be validated"
                )
            patterns.extend(values)
        if name in {"eq", "equal", "internal.member_2"} and len(args) == 2:
            for left, right in (args, list(reversed(args))):
                if resolved(left) in {
                    ("input", "tool", "id"),
                    ("input", "tool", "name"),
                }:
                    if right.get("type") in {"array", "set"}:
                        tools.update(
                            v for item in right["value"] for v in literals(item)
                        )
                    else:
                        tools.update(literals(right))

    uses_input = False
    uses_tool = False
    for ref in references:
        if not ref:
            continue
        if ref[0] == "data":
            raise ConditionError(
                "external data references are not supported in generated conditions"
            )
        if ref[0] != "input":
            continue
        uses_input = True
        if len(ref) > 1 and ref[1] not in _ROOTS:
            raise ConditionError(f"unknown or removed policy-input member {ref[1]!r}")
        if len(ref) > 1 and ref[1] == "tool":
            uses_tool = True
            if point not in {"pre_tool_call", "post_tool_call"}:
                raise ConditionError(f"input.tool is null at '{point}'")
        if len(ref) > 2 and ref[1] == "annotations":
            if not isinstance(ref[2], str):
                raise ConditionError(
                    "annotation names must be literal; use input.annotations.name"
                )
            annotators.add(ref[2])
        if (
            ref[:2] == ("input", "policy_target")
            and len(ref) > 2
            and ref[2] not in {"value", "kind", "path"}
        ):
            raise ConditionError(f"unknown policy_target member {ref[2]!r}")
        if ref[:3] == ("input", "policy_target", "value") and len(ref) > 3:
            if point == "pre_model_call" and isinstance(ref[3], str):
                raise ConditionError(
                    "pre_model_call target is an array; iterate over messages"
                )
            members = _OBJECT_MEMBERS.get(point)
            if members is not None and ref[3] not in members:
                raise ConditionError(
                    f"unsupported target member {ref[3]!r} at '{point}'"
                )
    if ("input", "annotations") in references and not annotators:
        raise ConditionError("annotation dependencies must name specific annotators")
    if not uses_input:
        raise ConditionError(
            "a constant body selects every request or none; conditions must read input"
        )
    return ConditionInfo(
        tuple(dict.fromkeys(patterns)),
        frozenset(annotators),
        frozenset(tools),
        uses_tool,
    )
