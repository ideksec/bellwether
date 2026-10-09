"""The request shape a provider endpoint is expected to receive (§10.5.2).

The model API is the one authenticated, allowlisted channel out of the sandbox, and the proxy
puts the operator's real key on every request to it (§10.5.1). "To it" was, until this module,
"to its host": any method, any path, any model. A skill holding the sandbox-scoped token could
``POST /v1/files`` — an upload to the provider on the operator's account, a destination the
canary body scan skips because it is the model channel — or drive a model the matrix never
priced, and the proxy would swap the real key in on the way out. §10.5.2's rule is that a request
to the provider must match the expected endpoint path and carry a model ID from the configured
set, and that an arbitrary POST to another endpoint on the provider's domain is a ``high`` finding
of type ``unexpected_provider_endpoint``.

This module is the rule, kept pure. It is an allowlist in every clause: the paths a provider
type is expected to receive are named per type, the model set is the one ``config.yaml``
declares, and a path is compared only after it has been reduced to a plain segment spelling —
a spelling the proxy cannot reduce (a percent escape, a dot segment, a doubled slash) is refused
rather than guessed at, because what the provider's server would make of it is not something
this side can know.

The expected paths are **observed, not assumed**: the pinned claude-code CLI (2.1.257), run
headless with an API key under the harness's telemetry environment against a scripted Messages
API, makes exactly ``POST /v1/messages?beta=true`` with the configured model, once per turn, and
nothing else — under both ``dontAsk`` and ``bypassPermissions``. ``count_tokens`` is the one
addition beyond that observation: it is the same body shape to the same API family, carries the
same ``model`` field this rule checks, and the CLI's SDK can call it under context pressure a
short session never reaches. The ``openai_compatible`` path is the one the host-side client
itself dials.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "PROVIDER_PATH_SUFFIXES",
    "ProviderRequestShape",
    "expected_request_paths",
    "request_shape",
    "shape_violation",
]

#: The request paths each provider type is expected to receive, relative to the ``base_url``
#: path. An allowlist per type; a type absent here has no known shape and :func:`request_shape`
#: refuses to build one rather than let its traffic through unchecked.
PROVIDER_PATH_SUFFIXES: Mapping[str, tuple[str, ...]] = {
    "anthropic": ("/v1/messages", "/v1/messages/count_tokens"),
    "openai_compatible": ("/chat/completions",),
}

#: The only method a model call uses. A ``GET`` on the provider — a model listing, a file
#: download — is not a model call, whatever its path.
_EXPECTED_METHOD = "POST"

#: A path the proxy can compare literally: slash-separated segments of plain characters, no
#: escapes, no dot segments, no empty segments. Anything outside this grammar is refused before
#: comparison — not because it is known to be an attack, but because its meaning to the
#: provider's server is not knowable here (``/v1/messages/../files`` and ``/v1/%66iles`` are
#: the two obvious spellings; the grammar refuses every unenumerated one too).
_PLAIN_SEGMENT = re.compile(r"^(?:/[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*)+$")


@dataclass(frozen=True)
class ProviderRequestShape:
    """What a request to one provider host must look like to be a model call (§10.5.2).

    ``paths`` are the exact request paths (query string excluded) the provider is expected to
    receive; ``model_ids`` is the configured set a request's ``model`` must name. Both are
    sorted tuples so the sidecar config built from them is byte-stable (§24).
    """

    paths: tuple[str, ...]
    model_ids: tuple[str, ...]


def expected_request_paths(provider_type: str, base_url: str) -> tuple[str, ...]:
    """The exact paths a provider of ``provider_type`` at ``base_url`` is expected to receive.

    The ``base_url`` path prefix is kept (a gateway at ``https://gw.example/anthropic`` expects
    ``/anthropic/v1/messages``), exactly as the host-side clients join it. A type with no entry
    in :data:`PROVIDER_PATH_SUFFIXES` raises: a provider whose shape is unknown must not be
    wired as one whose every request is expected.
    """
    try:
        suffixes = PROVIDER_PATH_SUFFIXES[provider_type]
    except KeyError:
        raise ValueError(
            f"no expected request shape is defined for provider type {provider_type!r}; "
            f"known types: {', '.join(sorted(PROVIDER_PATH_SUFFIXES))}"
        ) from None
    parsed = urlsplit(base_url if "://" in base_url else f"//{base_url}", scheme="https")
    prefix = parsed.path.rstrip("/")
    return tuple(sorted(f"{prefix}{suffix}" for suffix in suffixes))


def request_shape(
    provider_type: str, base_url: str, model_ids: Iterable[str]
) -> ProviderRequestShape:
    """Build the shape for one configured provider from its type, endpoint and model set."""
    return ProviderRequestShape(
        paths=expected_request_paths(provider_type, base_url),
        model_ids=tuple(sorted(set(model_ids))),
    )


def _model_of(body: bytes) -> str | None:
    """The ``model`` a JSON request body names, or ``None`` where it names none."""
    try:
        payload: Any = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    model = payload.get("model")
    return model if isinstance(model, str) else None


def shape_violation(*, method: str, path: str, body: bytes, shape: ProviderRequestShape) -> str:
    """Why this request to a provider host is not a model call, or ``""`` where it is one.

    Checked in the order a reader would ask the questions: the method, then the path (query
    string dropped, spelling reduced to the plain grammar or refused), then the model the body
    names. Every clause is positive — the request must match — so a request shape nobody has
    thought of is a violation, not a pass.
    """
    if method.upper() != _EXPECTED_METHOD:
        return (
            f"{method.upper()} to a provider host is not a model call (only "
            f"{_EXPECTED_METHOD} to {', '.join(shape.paths)} is expected, §10.5.2)"
        )
    bare = path.split("?", 1)[0].split("#", 1)[0]
    if not _PLAIN_SEGMENT.match(bare):
        return (
            f"request path {bare!r} is not a plain path the proxy can compare "
            "(an escape, a dot segment or an empty segment); refused rather than resolved "
            "(§10.5.2)"
        )
    if bare not in shape.paths:
        return (
            f"request path {bare!r} is not an expected provider endpoint "
            f"(expected one of {', '.join(shape.paths)}, §10.5.2)"
        )
    model = _model_of(body)
    if model is None:
        return (
            "the request body does not name a model (a model call carries a JSON `model` "
            "field, §10.5.2)"
        )
    if model not in shape.model_ids:
        return (
            f"model {model!r} is not in the configured set for this provider "
            f"({', '.join(shape.model_ids)}, §10.5.2)"
        )
    return ""
