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
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise PolicyError(f"invalid YAML{location}") from None
    except ValidationError:
        raise PolicyError("policy fields or values do not match the schema") from None


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
    schema["properties"]["mode"] = {
        "type": "string",
        "enum": ["audit", "enforce"],
        "default": "enforce",
    }
    schema["allOf"] = [
        {
            "if": {
                "anyOf": [
                    {"not": {"required": ["mode"]}},
                    {
                        "properties": {"mode": {"const": "enforce"}},
                        "required": ["mode"],
                    },
                ]
            },
            "then": {"properties": {"default": {"const": "deny"}}},
        }
    ]
    return schema


def policy_json_schema_text() -> str:
    return json.dumps(policy_json_schema(), indent=2, sort_keys=True)
