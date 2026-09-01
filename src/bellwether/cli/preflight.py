"""The §16.4 preflight: compose what this run could actually observe, then check it.

`verdict.precondition.check_preconditions` is deliberately pure — profile in, failures out —
which left it with no caller until now (BW-51: built, exported, unit-tested, wired nowhere).
What it needs that only this layer can supply is the *composition*: which capture planes the
configured executor will actually stand up, and what each target's adapter can observe once
that composition is overlaid on its static declaration.

Observability is configuration-dependent, and getting that wrong here is worse than not
checking at all — a preflight that reads the adapter's static ``egress_observable: False``
would refuse the proven live configuration (proxy wired, egress observed), and one that
assumed the proxy is always present would wave through the scaffold default (egress gate set
to ``block``, no proxy configured), which then burns the whole matrix before blocking on an
unobserved plane. So the rule is: a plane is available exactly when the config wires the
component that captures it, mirroring `run.build_proxy_provider` / `build_resolver_provider`
— the same predicates, read from the same fields.

Known bound, stated rather than hidden: ``requires.min_bellwether_version`` is not checked
here. Comparing versions needs a version-ordering rule this project has not committed to, and
the one profile that sets it (``high``) already refuses on its missing capture planes, so
skipping it cannot produce a false start today. It is tracked in STATUS as outstanding.
"""

from __future__ import annotations

from collections.abc import Sequence

from bellwether.cli.orchestrator import TargetInfo
from bellwether.config.models.config import Config
from bellwether.config.models.policy import ProfileSpec
from bellwether.errors import BellwetherError
from bellwether.harness import ApiLoopAdapter, ClaudeCodeAdapter
from bellwether.verdict import PreconditionFailure, TargetDeclaration, check_preconditions

__all__ = ["available_planes", "preflight_failures", "refuse_on_preflight_failures"]


def available_planes(config: Config) -> frozenset[str]:
    """The capture planes the configured composition will actually provide (§10.7).

    Availability means "the component that captures this plane is wired", never "the run
    will go well": harness events and the overlay diff are the executor's own mechanisms;
    canaries, the proxy, and the resolver exist exactly when config turns them on. The
    read and process planes are not built in this version (fanotify is v0.2, eBPF v0.3),
    so they are never available — which is what makes the ``high`` profile's
    ``requires.capture_planes`` refuse today, exactly as §16.4 intends.
    """
    planes = {"harness_events", "filesystem_writes"}
    if config.canaries.enabled:
        planes.add("credentials")
    if config.egress.image:
        planes.add("egress")
    if config.dns.image:
        planes.add("dns")
    return frozenset(planes)


def _declare(config: Config, target: TargetInfo) -> TargetDeclaration | PreconditionFailure:
    """One target's composed declaration, or the failure explaining why none exists.

    Two adapters ship: ``api-loop`` and ``claude-code``. Any other harness name must refuse
    *here*, before a container is paid for. A ``claude-code`` target additionally needs the
    recording proxy wired: the CLI's model calls originate inside the sandbox and have no
    route out except the proxy, which is also where the sandbox-scoped token is swapped for
    the real key (§3.3 invariant 1) — without ``egress.image`` the run would spend a container
    to watch the CLI fail to reach any model. The static adapter declaration is overlaid with
    the composition-scoped observability bits (proxy → egress, resolver → DNS), which the
    adapter alone cannot know.
    """
    if target.harness == "api-loop":
        capabilities = dict(ApiLoopAdapter.capabilities().as_record())
    elif target.harness == "claude-code":
        if not config.egress.image:
            return PreconditionFailure(
                gate="matrix.required_targets",
                target=target.slug,
                remedy=(
                    "the claude-code harness reaches the model only through the recording "
                    "proxy (its calls originate inside the sandbox, and the proxy injects the "
                    "real key — §3.3 invariant 1); set egress.image in config.yaml to wire the "
                    "proxy sidecar, or use an api-loop target"
                ),
            )
        capabilities = dict(ClaudeCodeAdapter.static_capabilities().as_record())
    else:
        return PreconditionFailure(
            gate="matrix.required_targets",
            target=target.slug,
            remedy=(
                f"no adapter for harness '{target.harness}' ships in this build (api-loop and "
                "claude-code do); use one of those, or remove this target from the profile's "
                "matrix"
            ),
        )
    capabilities["egress_observable"] = bool(config.egress.image)
    capabilities["dns_observable"] = bool(config.dns.image)
    return TargetDeclaration(label=target.slug, provider=target.provider, capabilities=capabilities)


def preflight_failures(
    config: Config, profile: ProfileSpec, targets: Sequence[TargetInfo]
) -> list[PreconditionFailure]:
    """Every reason this profile cannot be satisfied by this composition, or an empty list.

    No-adapter targets are reported alongside the §16.4 check's own findings rather than
    short-circuiting it, so one doctor row or one refusal shows the whole picture instead
    of revealing failures one fix at a time.
    """
    failures: list[PreconditionFailure] = []
    declarations: list[TargetDeclaration] = []
    for target in targets:
        declared = _declare(config, target)
        if isinstance(declared, PreconditionFailure):
            failures.append(declared)
        else:
            declarations.append(declared)
    failures.extend(
        check_preconditions(profile, declarations, available_planes=available_planes(config))
    )
    return failures


def refuse_on_preflight_failures(
    config: Config, profile: ProfileSpec, targets: Sequence[TargetInfo], *, profile_name: str
) -> None:
    """Raise :class:`BellwetherError` in the §16.4 message shape if the matrix cannot start.

    Called by ``run_evaluation`` after resolution and before the executor is built, so an
    unsatisfiable policy costs an error message instead of a matrix.
    """
    failures = preflight_failures(config, profile, targets)
    if failures:
        rendered = "\n".join(failure.message(profile_name) for failure in failures)
        raise BellwetherError(
            f"the §16.4 precondition check found {len(failures)} unsatisfiable "
            f"requirement(s); refusing before any run is paid for:\n{rendered}"
        )
