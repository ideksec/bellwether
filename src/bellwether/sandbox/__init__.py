"""Sandbox lifecycle: containers, mounts, fixtures, canary planting, teardown (§9).

Responsibility
    The eleven steps of §9.1: materialise a fixture with normalized mtimes, modes and
    ownership; plant canaries; install the skill payload by **allowlist** so ``evals/``
    never enters the container; mount the overlay with a host-side upper directory;
    start the capture planes and the proxy and resolver sidecars; run; read the overlay
    diff by zone; tear down.

MUST NOT
    Know about models. Anything model-shaped belongs to :mod:`bellwether.harness`.

Built by WP-4. The isolation profile of §9.2 (``--cap-drop=ALL``, ``--read-only``,
``--pids-limit 512``, ``no-new-privileges``, 900s default timeout) is achievable only
because no capture code runs inside the container (§10.0) — keep it that way.
"""

from __future__ import annotations

__all__: list[str] = []
