# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The authoring parser uses Regorus without evaluating the supplied source."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from agent_control_spec import _native
from agent_control_spec.authoring import REGORUS_AST_VERSION, parse_rego_ast


def test_regorus_ast_version_and_source_are_explicit():
    source = 'package test\nimport rego.v1\nrule if { input["text"] == "café" }\n'
    policies = parse_rego_ast(source)
    assert REGORUS_AST_VERSION == "0.12.0"
    assert policies[0]["version"] == 1
    assert policies[0]["source"]["contents"] == source
    assert policies[0]["ast"]["package"]["refr"]["Var"]["value"] == "test"
    assert policies[0]["ast"]["rego_v1"]


def test_parsing_does_not_compile_or_evaluate_builtins():
    # An unknown function would fail compilation/evaluation. Parsing preserves
    # the call so the authoring consumer can reject it without executing it.
    source = "package test\nrule := not_a_real_builtin(input)\n"
    assert "not_a_real_builtin" in json.dumps(parse_rego_ast(source))


@pytest.mark.parametrize("source", ["", "package", "package test\nx := ["])
def test_invalid_source_raises_value_error(source):
    with pytest.raises(ValueError, match="invalid Rego"):
        parse_rego_ast(source)


def test_authoring_size_limit_is_enforced_by_native_boundary():
    with pytest.raises(ValueError, match="65536"):
        _native.parse_rego_ast(" " * 65_537)


def test_parallel_parses_do_not_share_module_state():
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(parse_rego_ast, [f"package p{i}\nvalue := {i}" for i in range(8)])
        )
    assert [item[0]["ast"]["package"]["refr"]["Var"]["value"] for item in results] == [
        f"p{i}" for i in range(8)
    ]


def test_parsing_runs_with_an_empty_path():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from agent_control_spec.authoring import parse_rego_ast\n"
                "assert parse_rego_ast('package offline\\nvalue := 1')[0]['version'] == 1\n"
            ),
        ],
        env={**os.environ, "PATH": ""},
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
