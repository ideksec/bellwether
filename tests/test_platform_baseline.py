"""WP-8: the platform baseline (§12.6).

The two done-when criteria head the file: a benign run's infrastructural reads produce
zero spurious entries after subtraction, and `~/.cache/../.aws/credentials` raises a
near-miss finding rather than being absorbed.
"""

from __future__ import annotations

import pytest

from bellwether.assertions import (
    ObservedPath,
    ObservedProcess,
    apply_path_baseline,
    attribute_process,
    glob_to_regex,
)
from bellwether.config import parse_platform_baseline
from bellwether.config.models.baseline import PlatformBaseline
from bellwether.errors import ConfigurationError
from bellwether.trace import NormalizationContext, canonicalize

IMAGE = "ghcr.io/example/sandbox@sha256:" + "a" * 64


def make_baseline(**overrides: object) -> PlatformBaseline:
    data: dict[str, object] = {
        "apiVersion": "bellwether/v1",
        "kind": "PlatformBaseline",
        "version": "2026.08.1",
        "applies_to_image": IMAGE,
        "paths": {
            "read": [
                "/etc/{passwd,group,hosts,resolv.conf}",
                "/etc/ssl/**",
                "/usr/lib/**",
                "${HOME}/.cache/**",
                "${SKILL_INSTALL_PATH}/**",
            ],
            "write": ["${TMP}/**"],
        },
        "processes": {
            "always": ["sh", "dash", "env"],
            "helpers_of": {
                "git": ["git", "git-remote-https", "git-credential-*", "ssh"],
                "python3": ["python3", "python3.*"],
            },
        },
    }
    data.update(overrides)
    return parse_platform_baseline(data)


def observed(raw: str, resolved: str | None = None) -> ObservedPath:
    return ObservedPath(raw=raw, resolved=resolved if resolved is not None else raw)


# ---------------------------------------------------------------------------
# The done-when criteria
# ---------------------------------------------------------------------------


def test_a_benign_runs_infrastructure_produces_zero_spurious_entries() -> None:
    """The first done-when: the reads every run makes regardless of skill — libc,
    certificates, caches, the installed skill body — are all absorbed, and the two
    reads the skill actually performed are all that survive."""
    baseline = make_baseline()
    infrastructure = [
        observed("/etc/passwd"),
        observed("/etc/hosts"),
        observed("/etc/ssl/certs/ca-certificates.crt"),
        observed("/usr/lib/python3.12/os.py"),
        observed("${HOME}/.cache/pip/http/a1/b2.body"),
        observed("${SKILL_INSTALL_PATH}/SKILL.md"),
    ]
    skill_reads = [
        observed("${WORKSPACE}/src/auth.py"),
        observed("${WORKSPACE}/README.md"),
    ]

    application = apply_path_baseline(
        infrastructure + skill_reads, baseline, access="read", sandbox_image=IMAGE
    )

    assert application.absorbed == {path.resolved for path in infrastructure}
    assert application.near_misses == ()
    surviving = {p.resolved for p in infrastructure + skill_reads} - application.absorbed
    assert surviving == {"${WORKSPACE}/src/auth.py", "${WORKSPACE}/README.md"}


def test_a_traversal_through_the_cache_raises_a_near_miss_not_an_absorption() -> None:
    """The second done-when, verbatim from the build plan."""
    baseline = make_baseline()
    sneaky = ObservedPath(
        raw="${HOME}/.cache/../.aws/credentials",
        resolved="${HOME}/.aws/credentials",
    )

    application = apply_path_baseline([sneaky], baseline, access="read", sandbox_image=IMAGE)

    assert application.absorbed == frozenset()
    (near_miss,) = application.near_misses
    assert near_miss.kind == "traversal_past_entry"
    assert near_miss.severity == "medium"
    assert near_miss.rule == "${HOME}/.cache/**"
    assert ".aws" in near_miss.observed


# ---------------------------------------------------------------------------
# Traversal edges
# ---------------------------------------------------------------------------


def test_traversal_into_a_baseline_entry_is_flagged_not_matched() -> None:
    """`/etc/x/../passwd` resolves onto an entry; §12.6 says traversal never resolves
    *into* a match, and naming an entry via traversal is itself suspicious."""
    baseline = make_baseline()
    into = ObservedPath(raw="/etc/x/../passwd", resolved="/etc/passwd")

    application = apply_path_baseline([into], baseline, access="read", sandbox_image=IMAGE)

    assert application.absorbed == frozenset()
    (near_miss,) = application.near_misses
    assert near_miss.kind == "traversal_past_entry"


def test_traversal_unrelated_to_any_entry_is_neither_absorbed_nor_a_near_miss() -> None:
    baseline = make_baseline()
    unrelated = ObservedPath(raw="${WORKSPACE}/a/../b.txt", resolved="${WORKSPACE}/b.txt")

    application = apply_path_baseline([unrelated], baseline, access="read", sandbox_image=IMAGE)

    assert application.absorbed == frozenset()
    assert application.near_misses == ()


# ---------------------------------------------------------------------------
# Applicability (§12.6: keyed to the sandbox image)
# ---------------------------------------------------------------------------


def test_a_baseline_for_a_different_image_absorbs_nothing() -> None:
    baseline = make_baseline()
    other_image = "ghcr.io/example/sandbox@sha256:" + "b" * 64

    application = apply_path_baseline(
        [observed("/etc/passwd")], baseline, access="read", sandbox_image=other_image
    )
    assert application.absorbed == frozenset()

    applicable, reason = baseline.applicable_to(other_image)
    assert not applicable
    assert "different image" in reason or "different platform" in reason


def test_an_unkeyed_baseline_refuses_with_the_reason_stated() -> None:
    baseline = make_baseline(applies_to_image=None)
    applicable, reason = baseline.applicable_to(IMAGE)
    assert not applicable
    assert "placeholder" in reason

    application = apply_path_baseline(
        [observed("/etc/passwd")], baseline, access="read", sandbox_image=IMAGE
    )
    assert application.absorbed == frozenset()


# ---------------------------------------------------------------------------
# Glob semantics
# ---------------------------------------------------------------------------


def test_double_star_crosses_directories_and_single_star_does_not() -> None:
    deep = glob_to_regex("/usr/lib/**")
    assert deep.fullmatch("/usr/lib/python3.12/os.py")
    assert deep.fullmatch("/usr/lib/x")
    assert not deep.fullmatch("/usr/local/lib/x")

    shallow = glob_to_regex("${TMP}/*.log")
    assert shallow.fullmatch("${TMP}/run.log")
    assert not shallow.fullmatch("${TMP}/nested/run.log")


def test_brace_alternation_expands_including_nested() -> None:
    pattern = glob_to_regex("/etc/{passwd,ssl/{certs,private}/**}")
    assert pattern.fullmatch("/etc/passwd")
    assert pattern.fullmatch("/etc/ssl/certs/ca.crt")
    assert pattern.fullmatch("/etc/ssl/private/k/deep.pem")
    assert not pattern.fullmatch("/etc/group")


def test_placeholders_are_literal_not_special() -> None:
    """`${HOME}` contains regex metacharacters; a naive translation would make
    `${HOME}/.cache/**` match nothing — silently, in the direction that looks clean."""
    pattern = glob_to_regex("${HOME}/.cache/**")
    assert pattern.fullmatch("${HOME}/.cache/pip/wheel.whl")
    assert not pattern.fullmatch("/home/agent/.cache/pip/wheel.whl")
    assert not pattern.fullmatch("${HOME}/Xcache/pip/wheel.whl")


def test_question_mark_matches_one_character_within_a_segment() -> None:
    pattern = glob_to_regex("/dev/tty?")
    assert pattern.fullmatch("/dev/tty1")
    assert not pattern.fullmatch("/dev/tty12")
    assert not pattern.fullmatch("/dev/tty/1")


# ---------------------------------------------------------------------------
# Process attribution (§10.3, §12.6)
# ---------------------------------------------------------------------------


def test_a_helper_under_its_root_is_ordinary() -> None:
    baseline = make_baseline()
    attribution = attribute_process(
        ObservedProcess(argv0="git-remote-https", ancestors=("git", "sh")),
        baseline,
        declared=frozenset({"git"}),
    )
    assert attribution.verdict == "helper"
    assert attribution.accounted_for


def test_helper_name_patterns_match_with_wildcards() -> None:
    baseline = make_baseline()
    attribution = attribute_process(
        ObservedProcess(argv0="git-credential-store", ancestors=("git",)),
        baseline,
        declared=frozenset({"git"}),
    )
    assert attribution.verdict == "helper"


def test_a_curl_under_git_is_still_a_violation() -> None:
    """§10.3, verbatim."""
    baseline = make_baseline()
    attribution = attribute_process(
        ObservedProcess(argv0="curl", ancestors=("git",)),
        baseline,
        declared=frozenset({"git"}),
    )
    assert attribution.verdict == "unmatched"
    assert not attribution.accounted_for


def test_a_helper_without_its_parent_is_a_near_miss() -> None:
    """The §12.6 example: argv0 matches a helper, the parent does not."""
    baseline = make_baseline()
    attribution = attribute_process(
        ObservedProcess(argv0="git-remote-https", ancestors=("sh",)),
        baseline,
        declared=frozenset({"git"}),
    )
    assert attribution.verdict == "near_miss"
    assert attribution.near_miss is not None
    assert attribution.near_miss.kind == "helper_without_parent"
    assert attribution.near_miss.severity == "medium"


def test_an_undeclared_root_makes_its_helper_mapping_inert() -> None:
    """A standalone undeclared `git` is a plain violation, not a near-miss — and its
    helpers gain nothing from a mapping their root cannot use."""
    baseline = make_baseline()
    standalone = attribute_process(
        ObservedProcess(argv0="git", ancestors=("sh",)), baseline, declared=frozenset()
    )
    assert standalone.verdict == "unmatched"

    orphan_helper = attribute_process(
        ObservedProcess(argv0="git-remote-https", ancestors=("git",)),
        baseline,
        declared=frozenset(),
    )
    assert orphan_helper.verdict == "unmatched"


def test_always_processes_are_permitted_anywhere_in_the_tree() -> None:
    baseline = make_baseline()
    attribution = attribute_process(ObservedProcess(argv0="sh", ancestors=()), baseline)
    assert attribution.verdict == "baseline_always"


# ---------------------------------------------------------------------------
# Feeding canonicalization (§11.4: subtract before capability structures)
# ---------------------------------------------------------------------------


def test_the_absorbed_set_flows_into_canonicalize() -> None:
    import datetime as dt

    from bellwether.trace import Action

    baseline = make_baseline()
    ctx = NormalizationContext(workspace_root="/work/x1")
    events = [
        Action(
            seq=0,
            ts=dt.datetime(2026, 8, 6, tzinfo=dt.UTC),
            plane="harness",
            kind="tool_call",
            action={"tool": "read", "input": {"path": "/etc/passwd"}},
        ),
        Action(
            seq=1,
            ts=dt.datetime(2026, 8, 6, tzinfo=dt.UTC),
            plane="harness",
            kind="tool_call",
            action={"tool": "read", "input": {"path": "src/auth.py"}},
        ),
    ]
    application = apply_path_baseline(
        [observed("/etc/passwd"), observed("${WORKSPACE}/src/auth.py")],
        baseline,
        access="read",
        sandbox_image=IMAGE,
    )
    canonical = canonicalize(events, ctx, platform_baseline_t3=application.absorbed)

    assert "workspace_read" in canonical.caps_t1
    assert "outside_workspace_read" not in canonical.caps_t1
    assert len(canonical.step_sequence) == 2  # the sequence keeps the absorbed step


# ---------------------------------------------------------------------------
# The document and the shipped template
# ---------------------------------------------------------------------------


def test_the_shipped_template_parses_and_is_conservative() -> None:
    import yaml

    from bellwether.config import template_path

    data = yaml.safe_load(template_path("platform-baseline.yaml").read_text(encoding="utf-8"))
    baseline = parse_platform_baseline(data)

    assert baseline.applies_to_image is None, "the shipped default must not be pre-keyed"
    applicable, reason = baseline.applicable_to("any-image")
    assert not applicable and "placeholder" in reason
    assert baseline.tools == ()


def test_an_unknown_key_is_a_named_error() -> None:
    with pytest.raises(ConfigurationError):
        make_baseline(surprise="value")


def test_version_is_required() -> None:
    data = {
        "apiVersion": "bellwether/v1",
        "kind": "PlatformBaseline",
        "paths": {"read": [], "write": []},
    }
    with pytest.raises(ConfigurationError):
        parse_platform_baseline(data)
