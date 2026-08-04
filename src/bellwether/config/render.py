"""Turning pydantic validation failures into sentences (§21).

"All config MUST be validated with clear error messages that name the file, the path
within it, and the allowed values. Use pydantic and render validation errors as human
sentences, not stack traces."

A user meeting Bellwether for the first time meets it through a YAML error. This module
is the whole of that first impression, so it is worth more care than its size suggests.
"""

from __future__ import annotations

import difflib
import types
from typing import Annotated, Any, Union, get_args, get_origin

from pydantic import BaseModel, ValidationError

from bellwether.errors import UserFacingProblem

__all__ = ["problems_from_validation_error", "render_location"]

_MESSAGE_PREFIXES = (
    ("Input should be ", "must be "),
    ("Value error, ", ""),
    ("Assertion failed, ", ""),
)


def render_location(loc: tuple[str | int, ...]) -> str:
    """Render a pydantic error location as a dotted path a user can find in the file.

    Pydantic tags union and validator branches into the location tuple; those are
    implementation detail and are dropped, because ``sandbox.function-after[_check(),
    SandboxConfig].pids_limit`` names nothing a user can look at.
    """
    parts: list[str] = []
    for entry in loc:
        if isinstance(entry, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{entry}]"
            else:
                parts.append(f"[{entry}]")
        elif _is_internal_tag(entry):
            continue
        else:
            parts.append(entry)
    return ".".join(parts)


def _is_internal_tag(entry: str) -> bool:
    return "[" in entry or entry in {"function-after", "function-before", "union"}


def problems_from_validation_error(
    error: ValidationError,
    model: type[BaseModel] | None = None,
) -> list[UserFacingProblem]:
    """Convert a :class:`ValidationError` into sentences, sorted by location."""
    problems: list[UserFacingProblem] = []
    for raw in error.errors():
        loc = tuple(raw["loc"])
        kind = raw["type"]
        ctx = raw.get("ctx") or {}
        path = render_location(loc)

        if kind == "missing":
            problems.append(
                UserFacingProblem(path, "required field is missing", _sibling_hint(model, loc))
            )
            continue

        if kind == "extra_forbidden":
            name = str(loc[-1]) if loc else "?"
            parent = _model_at(model, loc[:-1]) if model else None
            problems.append(
                UserFacingProblem(
                    path,
                    f"unknown field {name!r}",
                    _unknown_field_hint(parent, name),
                )
            )
            continue

        message = _humanise(raw["msg"])
        hint: str | None = None
        expected = ctx.get("expected")
        if kind in {"literal_error", "enum"} and expected:
            message = f"must be one of {expected}"
            hint = None
        given = raw.get("input")
        if _is_scalar(given):
            message = f"{message} (got {given!r})"
        problems.append(UserFacingProblem(path, message, hint))

    return sorted(problems, key=lambda problem: (problem.path, problem.message))


def _humanise(message: str) -> str:
    for prefix, replacement in _MESSAGE_PREFIXES:
        if message.startswith(prefix):
            message = replacement + message[len(prefix) :]
            break
    return message[:1].lower() + message[1:] if message else message


def _is_scalar(value: Any) -> bool:
    return isinstance(value, str | int | float | bool) and not isinstance(value, type)


def _unknown_field_hint(parent: type[BaseModel] | None, name: str) -> str | None:
    if parent is None:
        return None
    known = sorted(_field_names(parent))
    if not known:
        return None
    close = difflib.get_close_matches(name, known, n=1, cutoff=0.6)
    if close:
        return f"did you mean {close[0]!r}? Known fields: {', '.join(known)}"
    return f"known fields: {', '.join(known)}"


def _sibling_hint(model: type[BaseModel] | None, loc: tuple[str | int, ...]) -> str | None:
    parent = _model_at(model, loc[:-1]) if model else None
    if parent is None:
        return None
    missing = str(loc[-1]) if loc else ""
    others = sorted(
        name
        for name, field in parent.model_fields.items()
        if field.is_required() and name != missing
    )
    if not others:
        return None
    return f"other required fields here: {', '.join(others)}"


def _field_names(model: type[BaseModel]) -> set[str]:
    names: set[str] = set()
    for name, field in model.model_fields.items():
        alias = field.validation_alias
        if isinstance(alias, str):
            names.add(alias)
        elif alias is not None and hasattr(alias, "choices"):
            names.update(choice for choice in alias.choices if isinstance(choice, str))
        else:
            names.add(name)
    return names


def _model_at(model: type[BaseModel] | None, loc: tuple[str | int, ...]) -> type[BaseModel] | None:
    """Walk a location path down from ``model`` and return the model class it lands on.

    Best-effort: any shape this does not understand yields ``None``, which costs a hint
    rather than producing a wrong one.
    """
    if model is None:
        return None
    current: Any = model
    for entry in loc:
        current = _unwrap(current)
        if isinstance(current, type) and issubclass(current, BaseModel) and isinstance(entry, str):
            if _is_internal_tag(entry):
                continue
            field = current.model_fields.get(entry) or _field_by_alias(current, entry)
            if field is None:
                return None
            current = field.annotation
            continue
        origin = get_origin(current)
        args = get_args(current)
        if origin is dict and args:
            current = args[1]
            continue
        if origin in {list, set, tuple} and args:
            current = args[0]
            continue
        return None
    current = _unwrap(current)
    if isinstance(current, type) and issubclass(current, BaseModel):
        return current
    return None


def _field_by_alias(model: type[BaseModel], name: str) -> Any:
    for field in model.model_fields.values():
        alias = field.validation_alias
        if alias == name:
            return field
        if alias is not None and hasattr(alias, "choices") and name in alias.choices:
            return field
    return None


def _unwrap(annotation: Any) -> Any:
    """Strip ``Annotated`` wrappers and pick the model branch out of an optional union."""
    for _ in range(8):
        origin = get_origin(annotation)
        if origin is Annotated:
            annotation = get_args(annotation)[0]
            continue
        if origin in {Union, types.UnionType}:
            branches = [arg for arg in get_args(annotation) if arg is not type(None)]
            models = [
                branch
                for branch in branches
                if isinstance(_strip(branch), type) and issubclass(_strip(branch), BaseModel)
            ]
            annotation = models[0] if models else (branches[0] if branches else annotation)
            continue
        return annotation
    return annotation


def _strip(annotation: Any) -> Any:
    return get_args(annotation)[0] if get_origin(annotation) is Annotated else annotation
