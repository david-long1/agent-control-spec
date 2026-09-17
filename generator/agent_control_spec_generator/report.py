# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Render the human review report shipped beside each generated policy."""

from __future__ import annotations

from typing import Any

from .plan import PolicyPlan


def build_report(
    plan: PolicyPlan, slug: str, manifest: dict[str, Any], warnings: list[str]
) -> str:
    lines = [
        f"# ACS generator report: {slug}",
        "",
        (
            "This policy is a model-generated draft for review. Do not activate it without "
            "checking its rules against your requirements and testing representative inputs."
        ),
        "",
        "## Checks performed",
        "",
        "- Regorus parsed the condition bodies in process; the generator checked supported references and functions.",
        "- ACS validated the manifest and compiled its in-memory Rego bundle.",
        "- The runtime regex engine accepted the collected patterns.",
        "- ACS accepted each transform path's grammar, independent of rule matching.",
        "- ACS evaluated synthetic contexts at each bound point with empty host annotations.",
        "",
        "## Limits",
        "",
        (
            "These checks do not prove that a rule fires when intended, that the policy covers "
            "every requirement, or that it handles your application's data shapes. In particular, "
            "a smoke evaluation returning allow does not prove the blocking rules work."
        ),
        "",
        (
            "No annotator service was called. Configure host dispatchers and test their actual "
            "outputs before use. Regex compilation checks syntax, not matching coverage."
        ),
        "",
        (
            "Rules use a first-match chain ordered deny > escalate > transform > warn > allow. "
            "Plan order breaks ties. Only one matching rule contributes a verdict; warnings are "
            "not accumulated. Unmatched cases default to allow. Unbound points are outside this policy."
        ),
        "",
        "## Bindings",
        "",
    ]
    for point, config in manifest["intervention_points"].items():
        lines.append(f"- `{point}` reads `{config['policy_target']}`.")
        for name, binding in config.get("annotations", {}).items():
            lines.append(f"  - Host annotator `{name}` reads `{binding['from']}`.")
    lines.extend(["", "## Rules", ""])
    for rule in plan.rules:
        lines.append(f"### {rule.point}: {rule.reason}")
        lines.extend(["", f"Policy intent: `{rule.decision}`.", "", "```rego"])
        lines.extend(rule.conditions or ("true",))
        lines.extend(["```", ""])
    lines.extend(["## Host configuration", ""])
    labels = {item.name: item.labels for item in plan.annotators}
    for name, config in manifest.get("annotators", {}).items():
        expected = ", ".join(labels.get(name, ())) or "not specified"
        lines.append(f"- `{name}` ({config['type']}), expected labels: {expected}.")
    if not manifest.get("annotators"):
        lines.append("- No annotator bindings.")
    tools = manifest.get("tools", {})
    lines.append(
        "- Tool catalog: " + (", ".join(f"`{name}`" for name in tools) or "none") + "."
    )
    lines.append(
        "An unknown tool is denied when tool projection is enabled. Supply the complete inventory."
    )
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in dict.fromkeys(warnings))
    return "\n".join(lines) + "\n"
