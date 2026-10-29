"""Pure, bounded normalizers. Filesystem symlink resolution belongs at the adapter boundary."""

from __future__ import annotations

import ipaddress
import shlex
import unicodedata
from functools import cache
from urllib.parse import urlsplit

from .models import Policy, Request, thaw_json

SHELL_META = frozenset("|&;<>`$\n\r")
EXEC_FLAGS = frozenset({"-c", "--command", "--eval", "-exec", "-execdir", "-e"})
PATH_KEYS = frozenset(
    {
        "path",
        "paths",
        "file",
        "filename",
        "directory",
        "dir",
        "cwd",
        "source_path",
        "target_path",
        "file_path",
        "output_path",
        "destination_path",
        "working_directory",
    }
)
HOST_KEYS = frozenset({"url", "uri", "host", "hostname", "endpoint", "website", "web_url"})
COMMAND_KEYS = frozenset({"command", "cmd", "script", "shell", "argv"})


def _is_exec_capable_flag(argument: str) -> bool:
    for flag in EXEC_FLAGS:
        if argument == flag or argument.startswith(flag + "="):
            return True
        if len(flag) == 2 and flag.startswith("-") and not flag.startswith("--"):
            if argument.startswith(flag) and len(argument) > len(flag):
                return True
    return False


def _expand_path(path: str, policy: Policy) -> str:
    value = unicodedata.normalize("NFC", path)
    configured_variables = dict(policy.variables)
    variables = {"HOME": configured_variables.get("HOME", ""), **configured_variables}
    for name, replacement in variables.items():
        value = value.replace("${" + name + "}", replacement)
    if value == "~" or value.startswith("~/"):
        home = variables.get("HOME", "")
        if not home:
            raise ValueError("home directory is not configured")
        value = home + value[1:]
    elif value.startswith("~"):
        raise ValueError("unsupported home-directory form")
    if "${" in value:
        raise ValueError("undefined path variable")
    if not value.startswith("/"):
        base = variables.get("WORKSPACE")
        if not base:
            raise ValueError("relative path has no configured workspace")
        value = base.rstrip("/") + "/" + value
    parts: list[str] = []
    for part in value.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def normalize_path_pattern(pattern: str, policy: Policy) -> str:
    """Expand configured home/variable prefixes without changing glob segments."""
    if pattern.startswith("~") or "${" in pattern:
        return _expand_path(pattern, policy)
    return unicodedata.normalize("NFC", pattern)


def normalize_host(value: str) -> tuple[str, bool]:
    """Normalize a URL or host and return whether URL userinfo was present."""
    raw = value.strip()
    has_scheme = "://" in raw
    parsed = urlsplit(raw if has_scheme else "//" + raw)
    userinfo = parsed.username is not None or parsed.password is not None
    host = parsed.hostname
    if not host:
        raise ValueError("host is missing")
    try:
        return ipaddress.ip_address(host).compressed.lower(), userinfo
    except ValueError:
        host = unicodedata.normalize("NFC", host.rstrip(".")).encode("idna").decode("ascii").lower()
        labels = host.split(".")
        if (
            not host
            or any(not label or len(label) > 63 for label in labels)
            or any(not (character.isalnum() or character in ".-") for character in host)
            or any(label.startswith("-") or label.endswith("-") for label in labels)
        ):
            raise ValueError("invalid hostname") from None
        return host, userinfo


def _collect(values: object, keys: frozenset[str]) -> list[str]:
    output: list[str] = []
    if isinstance(values, dict):
        for key, value in values.items():
            normalized_key = str(key).lower()
            if normalized_key in keys or ("path" in keys and normalized_key.endswith("_path")):
                if isinstance(value, str):
                    output.append(value)
                elif isinstance(value, list):
                    if any(not isinstance(item, str) for item in value):
                        raise ValueError("path or host argument lists must contain only strings")
                    output.extend(value)
                else:
                    raise ValueError("path or host arguments must be strings or string lists")
            output.extend(_collect(value, keys))
    elif isinstance(values, list):
        for value in values:
            output.extend(_collect(value, keys))
    return output


def normalize_request(
    request: Request, policy: Policy
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Extract and normalize every recognized path, host and command argument."""
    args = thaw_json(request.args)
    paths = tuple(sorted({_expand_path(item, policy) for item in _collect(args, PATH_KEYS)}))
    hosts: list[str] = []
    flags: list[str] = []
    for item in _collect(args, HOST_KEYS):
        host, userinfo = normalize_host(item)
        hosts.append(host)
        if userinfo:
            flags.append("URL_USERINFO")
    commands: list[str] = []
    for item in _collect(args, COMMAND_KEYS):
        if any(character in item for character in SHELL_META):
            flags.append("SHELL_METACHARACTER")
        try:
            argv = tuple(shlex.split(item, posix=True))
        except ValueError as error:
            raise ValueError("malformed command") from error
        if any(_is_exec_capable_flag(arg) for arg in argv):
            flags.append("EXEC_CAPABLE_FLAG")
        commands.extend(argv)
    return paths, tuple(sorted(set(hosts))), tuple(commands), tuple(sorted(set(flags)))


def path_glob_match(pattern: str, path: str) -> bool:
    """Match slash-separated globs; only a whole `**` segment crosses directories."""
    from fnmatch import fnmatchcase

    pparts = pattern.split("/")
    vparts = path.split("/")

    @cache
    def match(pi: int, vi: int) -> bool:
        if pi == len(pparts):
            result = vi == len(vparts)
        elif pparts[pi] == "**":
            result = match(pi + 1, vi) or (vi < len(vparts) and match(pi, vi + 1))
        else:
            result = (
                vi < len(vparts) and fnmatchcase(vparts[vi], pparts[pi]) and match(pi + 1, vi + 1)
            )
        return result

    return match(0, 0)
