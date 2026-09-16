# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The review report that ships beside the generated artifacts.

The report exists because a model wrote the policy. It records what was
assumed, what the engine checked, and what no check can establish, so the
reviewer who has to approve the policy knows where to look.
"""

from __future__ import annotations

from typing import Any

from .plan import PolicyPlan
from .vocabulary import INTERVENTION_POINT_BY_NAME, POLICY_TARGET, TARGET_SHAPES

_NOT_ESTABLISHED = (
    (
        "That the policy expresses the intent of the prose. The engine checks the "
        "shape of a rule, never its meaning."
    ),
    (
        "That the rules are complete. A guardrail the prose implied but did not "
        "state produces no rule and no warning."
    ),
    (
        "That annotator labels and scores match what a real annotator returns. "
        "Smoke evaluation answers every annotator with an empty annotation."
    ),
    (
        "That regular expressions match the intended text. They are checked for "
        "compilation, not for coverage."
    ),
    "That the tool catalog matches the agent's real tools.",
)


def build_report(
    plan: PolicyPlan, slug: str, manifest: dict[str, Any], warnings: list[str]
) -> str:
    lines = [
        f"# ACS generator report: {slug}",
        "",
        (
            "A language model produced this policy from natural-language guardrails. "
            "It is a draft for review, not an approved control. Read every rule before "
            "binding it to an agent, and treat the sections below as the record a "
            "reviewer works from."
        ),
        "",
        "## What the engine checked",
        "",
        "- The manifest validates against the engine's manifest grammar.",
        "- The Rego module compiles under the engine that will evaluate it.",
        "- Every redact pattern compiles under the engine's regular expression engine.",
        (
            "- Every guarded intervention point returns a policy verdict, not a "
            "`runtime_error:*` fail-closed deny, on a well-formed agent-hooks context."
        ),
        "",
        "## What no check established",
        "",
    ]
    lines.extend(f"- {item}" for item in _NOT_ESTABLISHED)
    lines.extend(["", "## Guarded intervention points", ""])
    for point_name, config in manifest["intervention_points"].items():
        spec = INTERVENTION_POINT_BY_NAME[point_name]
        lines.append(
            f"- `{point_name}` evaluates `{POLICY_TARGET}` as "
            f"`{spec.policy_target_kind}`, which is {TARGET_SHAPES[point_name]}"
        )
        if config.get("tool_name_from"):
            lines.append(f"  - projects the tool named at `{config['tool_name_from']}`")
        for annotator, binding in config.get("annotations", {}).items():
            lines.append(f"  - annotates with `{annotator}` from `{binding['from']}`")
    lines.extend(["", "## Rules", ""])
    if plan.rules:
        for rule in plan.rules:
            conditions = " and ".join(rule.conditions) or "unconditional"
            lines.append(
                f"- `{rule.point}` returns `{rule.decision}` with reason "
                f"`{rule.reason}` when {conditions}"
            )
    else:
        lines.append(
            "- No rule was produced, so every point returns the default allow."
        )
    lines.extend(["", "## Annotators", ""])
    if plan.annotators:
        for annotator in plan.annotators:
            labels = ", ".join(annotator.labels) or "none declared"
            lines.append(
                f"- `{annotator.name}` of type `{annotator.type}` is expected to "
                f"return: {labels}. The host supplies the dispatcher."
            )
    else:
        lines.append("- None. The policy decides on the policy target alone.")
    lines.extend(["", "## Tools", ""])
    tools = manifest.get("tools", {})
    if tools:
        lines.extend(f"- `{name}`" for name in tools)
    else:
        lines.append(
            "- None. No tool is projected, so `input.tool` is null at every point."
        )
    if warnings or plan.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in [*plan.warnings, *warnings])
    lines.append("")
    return "\n".join(lines)
