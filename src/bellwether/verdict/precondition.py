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
   controlled resolver (``dns.image``) are wired independently;
5. a mandatory policy control this build cannot satisfy — ``static.require_scan`` with no
   scanner shipped, ``scope.require_manifest`` against a package with no manifest,
   ``human_review.required`` with no attestation, ``separate_reviewer_from_author`` with no
   GitHub API call. Each of these was accepted by the schema and enforced nowhere until the
   review that found them; refusing here is what keeps "required" from meaning "printed".

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

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from bellwether.config.models.policy import ProfileSpec

__all__ = ["PreconditionFailure", "TargetDeclaration", "check_preconditions"]

#: A dotted-version component, split into its leading integer and whatever trails it.
_VERSION_COMPONENT = re.compile(r"^(\d+)(.*)$")


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


def _parse_version(version: str) -> tuple[tuple[int, ...], bool] | None:
    """Split a version into its ordering key: ``(release-segment, is-final)``.

    The **release segment** is the leading run of dot-separated integer components; a
    version carrying any further suffix (a ``.dev0``, ``rc1``, ``1.0.post2``, ``+local`` …)
    is a *pre-release of* that segment and sorts strictly below the bare release. Returns
    ``None`` for a string with no leading integer at all — a version this rule declines to
    order rather than guess at.

    This is the committed ordering rule (see :func:`_min_version_failure`): a deliberately
    conservative subset of PEP 440, enough to gate ``min_bellwether_version`` without a
    packaging dependency. It orders the simple ``MAJOR.MINOR[.PATCH]`` versions the policy
    uses, and every unknown suffix — including ``post`` releases PEP 440 would rank *above*
    the base — is treated as "below", so the rule can only ever refuse a borderline start,
    never falsely admit one.
    """
    release: list[int] = []
    final = True
    for part in version.strip().split("."):
        match = _VERSION_COMPONENT.match(part)
        if match is None:
            # A component with no leading integer (``dev0``, ``rc1``) begins the suffix.
            final = False
            break
        release.append(int(match.group(1)))
        if match.group(2):
            # Trailing non-digits on an otherwise-numeric component (``3rc1``) — a marker.
            final = False
            break
    if not release:
        return None
    return tuple(release), final


def _version_lt(lower: tuple[tuple[int, ...], bool], upper: tuple[tuple[int, ...], bool]) -> bool:
    """``lower < upper`` under the committed ordering, comparing release then finality."""
    lower_release, lower_final = lower
    upper_release, upper_final = upper
    width = max(len(lower_release), len(upper_release))
    lower_padded = lower_release + (0,) * (width - len(lower_release))
    upper_padded = upper_release + (0,) * (width - len(upper_release))
    if lower_padded != upper_padded:
        return lower_padded < upper_padded
    # Equal release segments: a pre-release sorts below the same final release.
    return (not lower_final) and upper_final


def _min_version_failure(minimum: str, running: str) -> PreconditionFailure | None:
    """Refuse if ``running`` is below the policy's ``min_bellwether_version`` (§16.4).

    An unparseable ``minimum`` is itself a start-blocking fault: the check cannot promise
    the requirement is met, so it refuses with a remedy rather than waving the run through.
    """
    minimum_key = _parse_version(minimum)
    if minimum_key is None:
        return PreconditionFailure(
            gate="requires.min_bellwether_version",
            target="(runner)",
            remedy=(
                f"requires.min_bellwether_version is set to {minimum!r}, which is not a "
                "recognisable version (expected a dotted release such as '0.3'); correct the "
                "policy, or remove the requirement"
            ),
        )
    running_key = _parse_version(running)
    if running_key is None or _version_lt(running_key, minimum_key):
        return PreconditionFailure(
            gate="requires.min_bellwether_version",
            target="(runner)",
            remedy=(
                f"this policy requires Bellwether >= {minimum} but the running version is "
                f"{running}; upgrade Bellwether, or lower requires.min_bellwether_version"
            ),
        )
    return None


def check_preconditions(
    profile: ProfileSpec,
    targets: Sequence[TargetDeclaration],
    *,
    available_planes: frozenset[str] = frozenset(),
    running_version: str | None = None,
    manifest_present: bool | None = None,
    review_state: str | None = None,
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
        running_version: The Bellwether version this run would execute under, supplied by
            the composition layer (``cli/preflight.py``) so this function stays pure. When
            ``None`` the ``requires.min_bellwether_version`` clause is not evaluated — a
            caller that cannot name the running version cannot make the comparison.
        manifest_present: Whether the package carries a ``declared_scope`` manifest, for the
            ``scope.require_manifest`` clause. ``None`` (the caller did not say) does not
            refuse: a check that guessed would refuse runs that are fine. The composition
            gate defers on the same input, so an unreported fact is disclosed there.
        review_state: ``SkillPackage.review_state()`` — ``absent`` / ``stale`` / ``current`` —
            for the ``human_review.required`` clause. A ``stale`` attestation is *not* refused
            here: staleness is a property of the bytes under evaluation and belongs in the
            verdict, where the reader can see which digest was reviewed.
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

    # (6) Mandatory policy controls this build cannot satisfy. Each of these was accepted by
    # the schema, printed in the resolved policy, and enforced nowhere — the silent-no-op shape
    # §16.4 exists to catch, reached through the policy document instead of through the planes.
    # Refusing here means the operator learns before the matrix is paid for; the matching gates
    # in the composition are the last line of defence for a path that skips this check.
    if gates.static.require_scan and "static_scan" not in available_planes:
        failures.append(
            PreconditionFailure(
                gate="static.require_scan",
                target="(runner)",
                remedy=(
                    "the policy requires a static scan but this build ships no static scanner "
                    "(§15 is a later work package), so no scan evidence can exist and the static "
                    "gate would be not_evaluable; set static.require_scan: false to state that a "
                    "scan is not required, or run a build that ships the scanner"
                ),
            )
        )
    if gates.scope.require_manifest and manifest_present is False:
        failures.append(
            PreconditionFailure(
                gate="scope.require_manifest",
                target="(package)",
                remedy=(
                    "the policy requires a declared_scope manifest and this package has none; "
                    "add bellwether.yaml (`bellwether init-manifest` drafts one from a probe "
                    "run), or set scope.require_manifest: false"
                ),
            )
        )
    if gates.human_review.required:
        if review_state in {None, "absent"}:
            failures.append(
                PreconditionFailure(
                    gate="human_review.required",
                    target="(package)",
                    remedy=(
                        "the policy requires a human review attestation and the manifest records "
                        "no metadata.review.last_human_review (§6.3); record one against the "
                        "current package_digest, or set human_review.required: false"
                    ),
                )
            )
        if gates.human_review.separate_reviewer_from_author:
            failures.append(
                PreconditionFailure(
                    gate="human_review.separate_reviewer_from_author",
                    target="(runner)",
                    remedy=(
                        "separation of duties is evaluated against the GitHub API (§6.3) — the "
                        "reviewers list in a manifest is written by the author and cannot "
                        "establish it — and this build makes no such call, so the constraint "
                        "would be not_evaluable; set separate_reviewer_from_author: false, or "
                        "enforce the separation in branch protection instead"
                    ),
                )
            )

    # (2) Required capture planes the runner cannot provide, and the minimum Bellwether
    # version. Both live under `requires` (§16.4): the version bound catches a policy that
    # names evidence a *future* build produces — it refuses the same run the missing-plane
    # clause does, one rung earlier and with a version-shaped remedy, so a policy written
    # against v0.3 fails clearly on a v0.1 runner instead of only via its planes.
    if profile.requires is not None:
        if profile.requires.min_bellwether_version is not None and running_version is not None:
            version_failure = _min_version_failure(
                profile.requires.min_bellwether_version, running_version
            )
            if version_failure is not None:
                failures.append(version_failure)
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
