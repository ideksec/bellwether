"""Every policy control the schema accepts must enforce a gate, or say why it does not (§16.1).

This file exists because of a repeat. The project's signature defect is a control path that
renders a clean result without running the check, and the *policy document* turned out to be a
route to it that nobody was watching: a field is added to a gate model, it validates, it prints
in the resolved policy, `doctor` shows it, and the verdict composition never reads it. An
operator sees `require_scan: true` and a `ready` verdict and reasonably concludes the two are
related.

It has now been found four times, in four different sub-models — the `security_runtime`
dispositions (BW-49), `static.require_scan`, `scope.require_manifest`, and the whole
`human_review` gate, the last three by an independent review. Fixing them one at a time is what
a blacklist does: every reject-clause has an unenumerated spelling, and here the unenumerated
spelling is "the next field someone adds".

So the classification is an *allowlist*, and this is the test that makes it mandatory. A field
on any gate model must appear in `ENFORCING_GATE_CONTROLS` or in `ADVISORY_GATE_CONTROLS` with a
stated reason. A new control therefore cannot be merged without someone answering the question
"what does this do to the verdict?" — at authoring time, where the answer is cheap, rather than
in a review of a shipped verdict that skipped a check.
"""

from __future__ import annotations

import inspect

import pytest

from bellwether.cli.orchestrator import (
    ADVISORY_GATE_CONTROLS,
    ENFORCED_SECURITY_RUNTIME_DISPOSITIONS,
    ENFORCING_GATE_CONTROLS,
)
from bellwether.config.models import policy as policy_models
from bellwether.config.models.policy import Gates, SecurityRuntimeGate


def _declared_controls() -> set[str]:
    """Every ``<gate>.<field>`` the policy schema accepts, read off the models themselves.

    Off the models, never from a hand-kept list: a list of controls that has to be updated
    alongside the models is the same kind of thing as a gate that has to be wired alongside the
    schema, and it would rot the same way.
    """
    controls: set[str] = set()
    for gate_name, field in Gates.model_fields.items():
        model = field.annotation
        assert model is not None and inspect.isclass(model), gate_name
        for control in model.model_fields:
            controls.add(f"{gate_name}.{control}")
    return controls


def test_every_accepted_control_is_classified() -> None:
    """The guard itself. An unclassified field is a control whose effect on the verdict nobody
    has stated, which is exactly the state every one of these defects was found in."""
    classified = set(ENFORCING_GATE_CONTROLS) | set(ADVISORY_GATE_CONTROLS)
    # The security_runtime dispositions are classified by their own constant, which `doctor`
    # also reads — one list, so the registry and the operator-facing message cannot disagree.
    for name in SecurityRuntimeGate.model_fields:
        classified.add(f"security_runtime.{name}")

    unclassified = sorted(_declared_controls() - classified)

    assert not unclassified, (
        "these policy controls are accepted by the schema but classified nowhere: "
        f"{unclassified}. Add each to ENFORCING_GATE_CONTROLS if a composed gate or the §16.4 "
        "precondition check reads it, or to ADVISORY_GATE_CONTROLS with the reason it cannot "
        "decide the verdict in this build. There is no third answer: a control the schema "
        "accepts and the composition ignores is the defect this registry exists to prevent."
    )


def test_the_registry_names_no_control_the_schema_does_not_have() -> None:
    """The other direction. A stale entry would quietly excuse a control that was renamed, and
    the next reader would take the registry's word for a field that no longer exists."""
    declared = _declared_controls()
    stale = sorted(
        name
        for name in (ENFORCING_GATE_CONTROLS | set(ADVISORY_GATE_CONTROLS))
        if name not in declared
    )

    assert not stale, f"the registry names controls the schema no longer has: {stale}"


def test_an_advisory_control_states_why_it_cannot_decide() -> None:
    """ "Advisory" is the answer an inert control would also like to give, so each one has to
    carry its reason in the registry — which puts it in front of the next reader."""
    for name, reason in ADVISORY_GATE_CONTROLS.items():
        assert reason.strip(), f"{name} is classified advisory with no stated reason"
        assert "§" in reason, f"{name}'s reason should cite the section that explains it"


def test_the_enforced_security_runtime_set_names_real_dispositions() -> None:
    """The pre-existing half of the registry, held to the same rule: `doctor` derives both the
    enforced and the inert list from this constant, so an entry naming a disposition that does
    not exist would silently shrink the "inert" warning an operator relies on."""
    unknown = sorted(ENFORCED_SECURITY_RUNTIME_DISPOSITIONS - set(SecurityRuntimeGate.model_fields))

    assert not unknown, f"enforced dispositions that are not fields on the gate: {unknown}"


@pytest.mark.parametrize(
    "control",
    ["static.require_scan", "scope.require_manifest", "human_review.required"],
)
def test_the_controls_this_review_found_inert_are_classified_enforcing(control: str) -> None:
    """Named individually so a future change that quietly demotes one to "advisory" has to
    delete a test that says what it was."""
    assert control in ENFORCING_GATE_CONTROLS


def test_the_policy_module_exposes_no_gate_model_the_registry_cannot_see() -> None:
    """`_declared_controls` walks `Gates`. A gate model defined in the policy module but never
    hung off `Gates` would be dead schema — accepted nowhere, or worse, accepted somewhere this
    walk does not reach."""
    hung = {field.annotation for field in Gates.model_fields.values()}
    defined = {
        obj
        for _, obj in inspect.getmembers(policy_models, inspect.isclass)
        if obj.__module__ == policy_models.__name__ and obj.__name__.endswith("Gate")
    }

    assert defined - hung == set(), (
        f"gate models defined but not reachable from Gates: {sorted(m.__name__ for m in defined - hung)}"
    )
