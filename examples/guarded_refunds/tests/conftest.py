# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared fixtures. Run with ``pytest examples/guarded_refunds/tests``."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

EXAMPLE_DIR = Path(__file__).resolve().parent.parent
if str(EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(EXAMPLE_DIR))

from app.annotators import LocalAnnotators
from app.host import activate


@pytest.fixture(scope="session")
def annotators() -> LocalAnnotators:
    return LocalAnnotators()


@pytest.fixture(scope="session")
def policy(annotators: LocalAnnotators):
    """Activated once for the whole run, exactly as a host would."""
    return activate(annotators)
