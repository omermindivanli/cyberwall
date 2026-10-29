"""Hermes plugin entrypoint for the source checkout."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path

_source = str(Path(__file__).resolve().parent / "src")
if _source not in sys.path:
    sys.path.insert(0, _source)

register = import_module("cyberwall.adapters.hermes.plugin").register

__all__ = ["register"]
