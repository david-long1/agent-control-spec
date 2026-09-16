# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The `acs-policy-gen` command."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from .engine import GenerationEngine, GenerationError
from .llm import DEFAULT_API_BASE, DEFAULT_MODEL, OpenAICompatibleLanguageModel
from .vocabulary import MAX_REPAIR_ATTEMPTS

_GENERATED_FILES = ("manifest.yaml", "report.md", "policy")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        out_dir = Path(args.out)
        if not args.dry_run:
            _check_out_dir(out_dir, force=args.force)
        model = OpenAICompatibleLanguageModel(
            api_base=args.api_base,
            api_key=args.api_key,
            model=args.model,
            api_version=args.api_version,
        )
        result = GenerationEngine(model, max_attempts=args.max_attempts).generate(
            prompt=_prompt(args),
            out_dir=out_dir,
            tool_inventory=_tool_inventory(args),
            write=not args.dry_run,
        )
    except (OSError, ValueError, GenerationError, RuntimeError) as exc:
        print(f"acs-policy-gen failed: {exc}", file=sys.stderr)
        return 1
    if args.dry_run:
        print(f"--- manifest.yaml ---\n{result.manifest_yaml}")
        print(f"--- policy/{result.slug}.rego ---\n{result.rego}")
        print(f"--- report.md ---\n{result.report}")
    else:
        print(
            f"Generated ACS artifacts for '{result.slug}' in {out_dir} "
            f"after {result.attempts} model call(s)."
        )
        print(
            "The policy is a model-generated draft. Review report.md and every rule "
            "before binding it to an agent."
        )
    if result.warnings:
        print("Warnings:", file=sys.stderr)
        for warning in result.warnings:
            print(f"  - {warning}", file=sys.stderr)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acs-policy-gen",
        description=(
            "Generate an ACS manifest and Rego policy from natural-language "
            "guardrails using a language model. Artifacts are validated by the "
            "engine that will run them and are written only after they pass. The "
            "result is a draft for human review, never an approved control."
        ),
        epilog=(
            "Output layout: manifest.yaml, policy/<slug>.rego, report.md. "
            "Credentials come from --api-key or ACS_GENERATOR_API_KEY and are "
            "never written to the output."
        ),
    )
    prompt = parser.add_mutually_exclusive_group(required=True)
    prompt.add_argument(
        "--prompt",
        help="Natural-language description of the agent, its policy, or both",
    )
    prompt.add_argument(
        "--prompt-file",
        help="File holding the description. Use - to read it from stdin",
    )
    parser.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME:LABEL,LABEL",
        help="Tool inventory entry as name:clearance1,clearance2. Repeatable",
    )
    parser.add_argument(
        "--tools-file",
        help="JSON or YAML object mapping tool names to tool catalog entries",
    )
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite manifest.yaml, report.md and policy/ in a non-empty output directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the artifacts instead of writing them",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=MAX_REPAIR_ATTEMPTS,
        help=(
            "Maximum model calls per generation, one per repair round "
            f"(default {MAX_REPAIR_ATTEMPTS})"
        ),
    )
    parser.add_argument(
        "--api-base",
        default=os.getenv("ACS_GENERATOR_API_BASE"),
        help=f"OpenAI-compatible API base URL (default {DEFAULT_API_BASE})",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("ACS_GENERATOR_API_KEY"),
        help="API key. Prefer ACS_GENERATOR_API_KEY so the key stays out of shell history",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("ACS_GENERATOR_MODEL"),
        help=f"Provider model or deployment name (default {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--api-version",
        default=os.getenv("ACS_GENERATOR_API_VERSION"),
        help="Azure OpenAI api-version. Setting it selects Azure api-key auth",
    )
    return parser


def _check_out_dir(out_dir: Path, *, force: bool) -> None:
    """Refuse to overwrite an output directory that holds anything else.

    Regenerating over a previous run is ordinary. Writing a policy into a
    directory that already holds unrelated work is not, and `--force` is the
    explicit way to say the generated files may be replaced.
    """
    if not out_dir.exists():
        return
    if not out_dir.is_dir():
        raise ValueError(f"--out {out_dir} exists and is not a directory")
    existing = sorted(entry.name for entry in out_dir.iterdir())
    if not existing:
        return
    if force:
        return
    unexpected = [name for name in existing if name not in _GENERATED_FILES]
    detail = (
        "it holds files this command does not generate: " + ", ".join(unexpected)
        if unexpected
        else "it holds artifacts from an earlier run"
    )
    raise ValueError(
        f"--out {out_dir} is not empty and {detail}. Pass --force to replace them"
    )


def _prompt(args: argparse.Namespace) -> str:
    if args.prompt_file == "-":
        return sys.stdin.read()
    if args.prompt_file:
        return Path(args.prompt_file).read_text(encoding="utf-8")
    return args.prompt


def _tool_inventory(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    if args.tools_file:
        raw = Path(args.tools_file).read_text(encoding="utf-8")
        loaded = (
            json.loads(raw)
            if args.tools_file.endswith(".json")
            else yaml.safe_load(raw)
        )
        if not isinstance(loaded, dict):
            raise ValueError(
                "--tools-file must contain a mapping of tool name to entry"
            )
        inventory.update(
            {str(name): dict(config or {}) for name, config in loaded.items()}
        )
    for entry in args.tool:
        name, separator, clearances = entry.partition(":")
        if not separator or not name:
            raise ValueError(
                f"--tool must use name:clearance1,clearance2, got '{entry}'"
            )
        labels = [part.strip() for part in clearances.split(",") if part.strip()]
        inventory[name] = {
            "type": "Tool",
            "id": name,
            "clearance": labels,
            "security_labels": labels,
        }
    return inventory


if __name__ == "__main__":
    raise SystemExit(main())
