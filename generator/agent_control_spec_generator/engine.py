# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Prose in, validated ACS artifacts out.

One generation is at most `MAX_REPAIR_ATTEMPTS` model calls. Each call
returns a plan, the plan is compiled, and the artifacts are validated by the
engine. A rejection becomes a concrete diagnostic that is fed back on the
next call, so the model repairs against what the engine actually said rather
than against a restatement of it. Every attempt failing raises
`GenerationError` carrying the whole diagnostic trail, and nothing is
written.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .llm import LanguageModel
from .manifest_builder import build_manifest, referenced_tool_names
from .plan import (
    PlanError,
    PolicyPlan,
    condition_regex_patterns,
    parse_policy_plan,
    redact_patterns,
)
from .rego_builder import build_rego
from .report import build_report
from .validation import ValidationError, dump_manifest_yaml, validate_artifacts
from .vocabulary import (
    ANNOTATOR_TYPES,
    INTERVENTION_POINT_NAMES,
    MAX_REPAIR_ATTEMPTS,
    TARGET_SHAPES,
    TRANSFORM_FORBIDDEN_POINTS,
)

_TARGET_TABLE = "\n".join(
    f"- {point}: $target is {TARGET_SHAPES[point]}"
    for point in INTERVENTION_POINT_NAMES
)
_FORBIDDEN_TRANSFORM_POINTS = " or ".join(sorted(TRANSFORM_FORBIDDEN_POINTS))

SYSTEM_PROMPT = f"""You author only a constrained JSON policy plan for Agent Control Specification artifacts.
Return JSON only. Do not emit YAML. Do not emit Rego modules.

Schema: {{name, guarded_points, annotators, annotations, tools, rules, warnings}}.
Valid intervention points: {", ".join(INTERVENTION_POINT_NAMES)}.
Annotator types: {", ".join(sorted(ANNOTATOR_TYPES))}.
Decisions: allow, warn, deny, escalate, transform. A warn becomes an allow carrying a warning, and an escalate becomes a deny carrying an approval block, so use warn for advisory findings and escalate for actions a human must approve.

Every rule sets "point" to one of the valid intervention points and carries at least one condition selecting when it fires, unless its decision is "allow" with no effects. An unconditional blocking rule fires on every request and is rejected.

Rule conditions are Rego body lines. They may read only input.intervention_point, input.annotations.<annotator>, input.policy_target.value, input.tool.name, input.tool.id, input.tool.clearance, input.snapshot, and constants. The policy input has exactly five members, which are intervention_point, policy_target, snapshot, annotations and tool. There is no input.request, input.resource, input.tools, input.stage or input.evidence.

input.policy_target.value is the value under control at the current point, and $target is the same value as a transform root. Its shape per point:
{_TARGET_TABLE}

To change the value under control, use decision "transform" with exactly one effect whose type is redact or replace and whose path begins with $target. allow, warn, deny and escalate must never carry effects. A redact effect needs a "pattern", which must be an RE2 regular expression, so no lookahead, no lookbehind and no backreferences. Point the path at the member holding the text, for example $target.content at input, post_model_call and output, because bare $target is an object at those points and a redaction rooted there can never fire. Never write $target.value, because the policy target already is the value. Never use transform at {_FORBIDDEN_TRANSFORM_POINTS}, where a host is required to reject it.

A reason must not begin with "runtime_error:", which is the engine's reserved namespace.

List every tool a rule gates on in "tools", because a tool absent from the manifest catalog makes every call to it fail closed.
"""


@dataclass(frozen=True)
class GenerationResult:
    slug: str
    manifest: dict[str, Any]
    manifest_yaml: str
    rego: str
    report: str
    warnings: tuple[str, ...]
    attempts: int


class GenerationError(RuntimeError):
    """Every attempt was rejected. Carries the diagnostic trail."""


class GenerationEngine:
    """Turns guardrail prose into validated ACS artifacts."""

    def __init__(
        self, language_model: LanguageModel, *, max_attempts: int = MAX_REPAIR_ATTEMPTS
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.language_model = language_model
        self.max_attempts = max_attempts

    def generate(
        self,
        *,
        prompt: str,
        out_dir: Path | None = None,
        tool_inventory: dict[str, dict[str, Any]] | None = None,
        write: bool = True,
    ) -> GenerationResult:
        """Generate, validate, and optionally write the artifacts.

        `write` requires `out_dir`. Writing happens only after validation
        passes, so a failed generation never leaves a partial policy on disk.
        """
        if write and out_dir is None:
            raise ValueError("out_dir is required when write is True")
        if not prompt or not prompt.strip():
            raise ValueError("prompt is empty; describe the agent and its guardrails")
        inventory = tool_inventory or {}
        repair_context = ""
        diagnostics: list[str] = []
        for attempt in range(1, self.max_attempts + 1):
            raw_plan = self.language_model.complete(
                SYSTEM_PROMPT, self._user_prompt(prompt, inventory, repair_context)
            )
            try:
                plan = parse_policy_plan(raw_plan)
                warnings = self._plan_warnings(plan, inventory)
                manifest, slug = build_manifest(plan, inventory)
                rego = build_rego(plan, slug)
                manifest_yaml = dump_manifest_yaml(manifest)
                result = validate_artifacts(
                    manifest,
                    manifest_yaml,
                    rego,
                    slug,
                    regex_patterns=redact_patterns(plan)
                    + condition_regex_patterns(plan),
                )
            except (PlanError, ValidationError) as exc:
                diagnostics.append(f"attempt {attempt}: {exc}")
                repair_context = self._repair_prompt(diagnostics)
                continue
            all_warnings = [*warnings, *result.warnings]
            generation = GenerationResult(
                slug=slug,
                manifest=manifest,
                manifest_yaml=manifest_yaml,
                rego=rego,
                report=build_report(plan, slug, manifest, all_warnings),
                warnings=tuple(all_warnings),
                attempts=attempt,
            )
            if write and out_dir is not None:
                self._write(out_dir, generation)
            return generation
        raise GenerationError(
            f"generation failed after {self.max_attempts} attempts:\n"
            + "\n".join(diagnostics)
        )

    def _user_prompt(
        self, prompt: str, inventory: dict[str, dict[str, Any]], repair_context: str
    ) -> str:
        tool_lines = (
            "\n".join(f"- {name}: {config}" for name, config in inventory.items())
            or "No tool inventory was provided."
        )
        return (
            f"Natural-language guardrails:\n{prompt}\n\n"
            f"Tool inventory:\n{tool_lines}\n\n{repair_context}"
        ).strip()

    def _repair_prompt(self, diagnostics: list[str]) -> str:
        return (
            "The previous plan was rejected. Repair only the failing part and preserve "
            "the rest of the intent. Diagnostics:\n" + "\n".join(diagnostics[-3:])
        )

    def _plan_warnings(
        self, plan: PolicyPlan, inventory: dict[str, dict[str, Any]]
    ) -> list[str]:
        warnings: list[str] = []
        undocumented = [
            name for name in referenced_tool_names(plan) if name not in inventory
        ]
        if undocumented:
            warnings.append(
                "Tools declared with minimal metadata because no inventory entry was "
                "supplied for them: " + ", ".join(undocumented)
            )
        dropped = sorted(
            {
                rule.reason or rule.decision
                for rule in plan.rules
                if rule.effects and rule.decision != "transform"
            }
        )
        if dropped:
            warnings.append(
                "Effects on non-transform decisions were dropped, because transform is "
                "the only value-changing verdict. Affected rules: " + ", ".join(dropped)
            )
        return warnings

    def _write(self, out_dir: Path, result: GenerationResult) -> None:
        """Stage the whole tree, then swap it in.

        A manifest names its bundle as a directory, and the engine loads every
        Rego file in it. A module left behind by an earlier run under a
        different slug is therefore still loaded, and one that does not
        compile fails activation for a policy that validated moments earlier.
        Writing in place also leaves the manifest and the policy installed
        against a stale report when the last write fails, so the new tree is
        built beside the target and moved over it.
        """
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{out_dir.name}.", dir=str(out_dir.parent))
        )
        try:
            (staging / "policy").mkdir()
            (staging / "manifest.yaml").write_text(
                result.manifest_yaml, encoding="utf-8"
            )
            (staging / "policy" / f"{result.slug}.rego").write_text(
                result.rego, encoding="utf-8"
            )
            (staging / "report.md").write_text(result.report, encoding="utf-8")
            previous = out_dir / "policy"
            if previous.is_dir():
                shutil.rmtree(previous)
            out_dir.mkdir(parents=True, exist_ok=True)
            for entry in staging.iterdir():
                shutil.move(str(entry), str(out_dir / entry.name))
        finally:
            shutil.rmtree(staging, ignore_errors=True)
