"""Strict policy parsing and schema generation; callers own all file I/O."""

from __future__ import annotations

import json
from typing import Any

import yaml
from pydantic import ValidationError

from .models import Policy


class PolicyError(ValueError):
    """Raised when policy text is malformed or has unknown fields."""


def load_policy_text(text: str) -> Policy:
    """Parse a YAML policy string with safe YAML constructors and strict models."""
    try:
        data: Any = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise PolicyError("policy root must be a mapping")
        return Policy.model_validate(data)
    except (yaml.YAMLError, ValidationError) as error:
        raise PolicyError(str(error)) from error


def policy_json_schema() -> dict[str, Any]:
    """Return the JSON Schema for the accepted policy model."""
    schema = Policy.model_json_schema(by_alias=True)
    schema["properties"]["variables"] = {
        "type": "object",
        "additionalProperties": {"type": "string"},
        "default": {},
    }
    schema["properties"]["tools"] = {
        "type": "object",
        "additionalProperties": {"$ref": "#/$defs/ToolDefinition"},
        "default": {},
    }
    return schema


def policy_json_schema_text() -> str:
    return json.dumps(policy_json_schema(), indent=2, sort_keys=True)
