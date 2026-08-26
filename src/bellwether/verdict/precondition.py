"""The precondition check: refuse before paying for the matrix (§16.4).

Several combinations in this specification fail only *after* a full matrix has run — a
40-minute, real-money way to learn the policy could never have been satisfied. The
precondition check compares the selected profile's requirements against the declared
capabilities of every target (§9.4) and the plane coverage the runner can actually
provide (§10.7), and refuses to start when they cannot be met. Every refusal names the
gate, the target, and the remedy, because "cannot start" without a remedy is a dead end.

The four cases the spec enumerates, each caught here:

1. an activation-blind harness (``generic-subprocess``) under
   ``require_all_should_trigger`` — ``skill_activated`` is ``not_evaluable``, so the gate
   can never pass;
2. a required capture plane the runner cannot provide — the ``high`` profile needs
   process capture, which ships in v0.3 and needs eBPF most managed runners deny;
3. ``min_distinct_providers: 2`` where the target matrix spans one provider — §14 forbids
   cross-harness divergence, so only a multi-provider matrix satisfies it;
4. a blocking egress or DNS gate against a target whose composition cannot observe that
   channel — checked per channel, because the recording proxy (``egress.image``) and the
   controlled resolver (``dns.image``) are wired independently.

Observability is a property of the *composition*, not the harness alone: an ``api-loop``
adapter provides no capture point itself, but the executor standing a recording proxy
beside the sandbox makes egress observed. The ``cli`` layer builds each
:class:`TargetDeclaration` from the adapter's static declaration overlaid with what the
config actually wires (`cli/preflight.py`), so this check reads the truth of the run
about to happen, not a stale static bit.

The same check is surfaced in ``bellwether doctor`` (§20), so a user learns before the run
rather than after it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from bellwether.config.models.policy import ProfileSpec

__all__ = ["PreconditionFailure", "TargetDeclaration", "check_preconditions"]


@dataclass(frozen=True)
class TargetDeclaration:
    """One matrix target and what its adapter declares it can observe (§9.4).

    ``capabilities`` is the ``HarnessCapabilities.as_record()`` form — a plain mapping so
    this layer stays decoupled from the harness module. ``provider`` feeds the
    distinct-provider count.
    """

    label: str
    provider: str
    capabilities: Mapping[str, object]

    def observes(self, capability: str) -> bool:
        return bool(self.capabilities.get(capability, False))


@dataclass(frozen=True)
class PreconditionFailure:
    """One reason the matrix cannot start, in the §16.4 message shape."""

    gate: str
    target: str
    remedy: str

    def message(self, profile_name: str) -> str:
        return (
            f"Cannot start: policy profile {profile_name!r} requires gate {self.gate!r} "
            f"but target {self.target!r} cannot satisfy it.\n  → {self.remedy}"
        )


def check_preconditions(
    profile: ProfileSpec,
    targets: Sequence[TargetDeclaration],
    *,
    available_planes: frozenset[str] = frozenset(),
) -> list[PreconditionFailure]:
    """Return every reason the matrix cannot satisfy the policy, or an empty list.

    The profile name is not needed here — each :class:`PreconditionFailure` renders it
    into the message via :meth:`PreconditionFailure.message`, so the caller supplies it
    once at the point of display.

    Args:
        profile: The resolved policy profile (already merged over ``defaults``).
        targets: The matrix targets with their declared capabilities.
        available_planes: The capture planes the current runner can actually provide
            (§10.7). A required plane absent from this set is an unsatisfiable gate, not a
            degraded run.
    """
    failures: list[PreconditionFailure] = []
    gates = profile.gates

    for target in targets:
        # (1) Activation-blind harness under require_all_should_trigger.
        if gates.functional.require_all_should_trigger and not target.observes(
            "structured_tool_events"
        ):
            failures.append(
                PreconditionFailure(
                    gate="functional.require_all_should_trigger",
                    target=target.label,
                    remedy=(
                        "this harness does not emit structured activation events, so "
                        "skill_activated is never evaluable; use a harness that does, or "
                        "set functional.require_all_should_trigger: false"
                    ),
                )
            )
        # (4) a blocking egress/DNS gate against a target that cannot observe that channel.
        # Split per channel rather than bundled: egress is observable when the recording proxy
        # is in the composition, DNS when the controlled resolver is — and they are configured
        # independently (`egress.image` / `dns.image`), so one being wired must not vouch for
        # the other. The composition layer sets both bits (`cli/preflight.py`); a harness alone
        # provides neither capture point.
        if gates.security_runtime.egress_outside_allowlist == "block" and not target.observes(
            "egress_observable"
        ):
            failures.append(
                PreconditionFailure(
                    gate="security_runtime.egress_outside_allowlist",
                    target=target.label,
                    remedy=(
                        "egress is not observable for this target (no recording proxy in the "
                        "composition), so the egress gate would be not_evaluable and block after "
                        "the matrix was paid for; configure egress.image to wire the proxy, or "
                        "set egress_outside_allowlist to 'warn'"
                    ),
                )
            )
        if gates.security_runtime.dns_outside_allowlist == "block" and not target.observes(
            "dns_observable"
        ):
            failures.append(
                PreconditionFailure(
                    gate="security_runtime.dns_outside_allowlist",
                    target=target.label,
                    remedy=(
                        "DNS is not observable for this target (no controlled resolver in the "
                        "composition); configure dns.image to wire the resolver, or set "
                        "dns_outside_allowlist to 'warn'"
                    ),
                )
            )

    # (5) a blocking canary gate with no credentials plane in the composition. The canary
    # gate is scored from Plane C findings (§10.4, §16.2); with canaries disabled no leak
    # evidence can ever exist, so the gate would sit not_evaluable and block after the
    # matrix was paid for. Runner-level, not per-target: planting is a composition property.
    if gates.security_runtime.canary_leak == "block" and "credentials" not in available_planes:
        failures.append(
            PreconditionFailure(
                gate="security_runtime.canary_leak",
                target="(runner)",
                remedy=(
                    "canaries are not planted in this composition (canaries.enabled: false), "
                    "so no leak evidence can exist and the canary gate would be not_evaluable; "
                    "enable canaries, or set canary_leak to 'warn'"
                ),
            )
        )
    # The canary-reads gate (§10.4.1) has the same composition dependency: with no canaries
    # planted, the model-channel scan has nothing to find and the gate would sit
    # not_evaluable after the matrix was paid for.
    if (
        gates.security_runtime.canary_without_read == "block"
        and "credentials" not in available_planes
    ):
        failures.append(
            PreconditionFailure(
                gate="security_runtime.canary_without_read",
                target="(runner)",
                remedy=(
                    "canaries are not planted in this composition (canaries.enabled: false), "
                    "so no unread-canary evidence can exist and the canary-reads gate would "
                    "be not_evaluable; enable canaries, or set canary_without_read to 'warn'"
                ),
            )
        )

    # (2) Required capture planes the runner cannot provide.
    if profile.requires is not None:
        missing = [p for p in profile.requires.capture_planes if p not in available_planes]
        for plane in sorted(set(missing)):
            failures.append(
                PreconditionFailure(
                    gate=f"requires.capture_planes[{plane}]",
                    target="(runner)",
                    remedy=(
                        f"the {plane} capture plane is not available on this runner; use "
                        "--profile medium, enable the plane in config, or run on a runner "
                        "that provides it"
                    ),
                )
            )

    # (3) min_distinct_providers unsatisfiable by the matrix.
    required_providers = profile.matrix.min_distinct_providers
    distinct = {target.provider for target in targets}
    if targets and len(distinct) < required_providers:
        failures.append(
            PreconditionFailure(
                gate="matrix.min_distinct_providers",
                target="(matrix)",
                remedy=(
                    f"the matrix spans {len(distinct)} provider(s) but the profile requires "
                    f"{required_providers}; add a target on a second provider, or lower "
                    "matrix.min_distinct_providers"
                ),
            )
        )

    return failures
