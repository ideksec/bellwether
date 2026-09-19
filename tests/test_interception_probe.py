"""WP-14's live half, offline: what a CA-in-the-loop probe establishes (§9.2, §20).

The dangerous state this exists for: a container that rejects the proxy's certificate makes no
observable egress, so the run produces a zero-egress trace that reads as a skill which never
touched the network. Doctor used to report the proxy as *configured* and stop there. These
tests pin the decision the probe feeds, and the command it runs; the container half is
`test_interception_probe_docker.py`.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from bellwether.capture import interpret_interception_probe
from bellwether.cli.interception_probe import (
    PROBE_CLIENT_SOURCE,
    PROBE_HOST,
    PROBE_SIDECAR_SETTINGS,
    probe_argv,
)

_CERT_ERROR = (
    "URLError <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
    "unable to get local issuer certificate (_ssl.c:1010)>"
)


def test_a_recorded_probe_host_confirms_the_chain_even_when_the_request_failed() -> None:
    """The load-bearing asymmetry: the proxy records a flow when it *receives* the request, so
    a recorded host proves the client accepted the proxy's certificate — whatever the upstream
    then did. That is what lets the probe use an unreachable host and no peer server."""
    probe = interpret_interception_probe(
        PROBE_HOST,
        [PROBE_HOST],
        exit_code=1,  # the client saw an error from the unreachable upstream
        stderr="HTTPError 502 Bad Gateway",
    )
    assert probe.confirmed
    assert not probe.ca_rejected and not probe.inconclusive
    assert "CA is trusted" in probe.reason


def test_a_rejected_certificate_is_named_as_the_dangerous_state() -> None:
    """No flow plus a certificate failure is the one state that must never read as anything
    but broken: every later run would look clean while observing nothing."""
    probe = interpret_interception_probe(PROBE_HOST, [], exit_code=1, stderr=_CERT_ERROR)
    assert not probe.confirmed
    assert probe.ca_rejected
    assert "no egress at all" in probe.reason and "reads as a skill" in probe.reason


def test_a_probe_that_never_reached_the_proxy_is_inconclusive_not_a_pass() -> None:
    """ "We could not tell" and "the CA is not trusted" call for different actions, and neither
    may be reported as a pass."""
    probe = interpret_interception_probe(PROBE_HOST, [], exit_code=127, stderr="python3: not found")
    assert not probe.confirmed
    assert not probe.ca_rejected
    assert probe.inconclusive
    assert "not a pass" in probe.reason


def test_an_unrelated_tls_error_is_not_reported_as_an_untrusted_ca() -> None:
    """The markers are about *trust*, not about TLS generally: a handshake that failed for
    another reason must not be blamed on the CA, or the operator fixes the wrong thing."""
    probe = interpret_interception_probe(
        PROBE_HOST, [], exit_code=1, stderr="ConnectionResetError [Errno 104] Connection reset"
    )
    assert probe.inconclusive and not probe.ca_rejected


def test_the_recorded_host_matching_folds_case_and_a_trailing_dot() -> None:
    """A casing or FQDN-dot mismatch must never read as a failed interception."""
    assert interpret_interception_probe(
        PROBE_HOST, [PROBE_HOST.upper() + "."], exit_code=0
    ).confirmed


def test_the_probe_runs_on_the_internal_bridge_with_the_runs_own_trust_environment() -> None:
    """The probe must prove the chain a *run* gets, not one assembled for the test: the client
    joins the sandbox's internal bridge (no route out but the proxy), the CA is mounted at the
    same container path the executor uses, and the environment is the run's own."""
    argv = probe_argv(
        image="sidecar@sha256:" + "a" * 64,
        network="bw-internal-xyz",
        environment={"HTTPS_PROXY": "http://proxy:8080", "SSL_CERT_FILE": "/ca.crt"},
        ca_host_path=Path("/tmp/ca.pem"),
    )
    assert argv[:5] == ["docker", "run", "--rm", "--network", "bw-internal-xyz"]
    assert "-e" in argv and "HTTPS_PROXY=http://proxy:8080" in argv
    assert "SSL_CERT_FILE=/ca.crt" in argv
    assert f"BW_PROBE_HOST={PROBE_HOST}" in argv
    # Read-only, at the §9.2 container trust path.
    assert any(
        part.endswith(":/usr/local/share/ca-certificates/bellwether-proxy.crt:ro") for part in argv
    )
    # A real interpreter runs a real request; the command is re-runnable by a human.
    assert argv[-3:-1] == ["python3", "-c"]
    assert "urllib.request" in argv[-1]


def test_the_probe_host_is_unresolvable_so_nothing_leaves_the_machine() -> None:
    """RFC 2606 reserves `.invalid`. The probe needs no reachable destination, so it must not
    have one: reaching the proxy is the whole of what is proven."""
    assert PROBE_HOST.endswith(".invalid")


def without_ca_trust(argv: list[str]) -> list[str]:
    """``argv`` with the CA bind and every CA-trust variable removed, keeping ``HTTPS_PROXY``.

    Used by the container proof's counter-case: the client still reaches the proxy, it just has
    no reason to believe its certificate. Lives here, beside the guard below, so a change to
    what carries trust fails offline rather than silently making the CI counter-case vacuous.
    """
    ca_vars = (
        "SSL_CERT_FILE=",
        "REQUESTS_CA_BUNDLE=",
        "CURL_CA_BUNDLE=",
        "NODE_EXTRA_CA_CERTS=",
        "GIT_SSL_CAINFO=",
    )
    out: list[str] = []
    index = 0
    while index < len(argv):
        part = argv[index]
        if part == "-e" and index + 1 < len(argv) and argv[index + 1].startswith(ca_vars):
            index += 2
            continue
        if part == "-v" and index + 1 < len(argv) and "ca-certificates" in argv[index + 1]:
            index += 2
            continue
        out.append(part)
        index += 1
    return out


def test_stripping_trust_removes_every_mechanism_and_keeps_the_route() -> None:
    """Guards the container proof's counter-case. If `probe_argv` ever names trust differently,
    the stripper stops matching — and this fails here rather than leaving a CI test that proves
    nothing because it silently stripped nothing."""
    from bellwether.capture.ca import CA_MECHANISMS

    environment = {"HTTPS_PROXY": "http://p:8080"}
    environment.update({mech.name: "/ca.crt" for mech in CA_MECHANISMS if mech.kind == "env"})
    argv = probe_argv(
        image="img", network="net", environment=environment, ca_host_path=Path("/tmp/ca.pem")
    )
    stripped = without_ca_trust(argv)

    # Every §9.2 environment mechanism is gone, and so is the mounted CA.
    for mech in CA_MECHANISMS:
        if mech.kind == "env":
            assert f"{mech.name}=/ca.crt" in argv
            assert f"{mech.name}=/ca.crt" not in stripped, mech.name
    assert not any("ca-certificates" in part for part in stripped)
    # The route to the proxy survives, so a failure is about trust and nothing else.
    assert "HTTPS_PROXY=http://p:8080" in stripped


def test_the_probe_defers_the_upstream_so_it_needs_no_reachable_destination() -> None:
    """The bug CI caught in the first cut. mitmproxy's default connection strategy is *eager*:
    it dials the upstream before the client handshake so the generated certificate can copy the
    real one. Under eager, an unresolvable probe host fails at connect and the request hook never
    fires — no flow, and the probe reports "inconclusive" forever. `lazy` completes the client
    handshake first, which is the whole reason the probe can use a destination that does not
    exist."""
    assert PROBE_SIDECAR_SETTINGS == {"connection_strategy": "lazy"}


def test_the_probes_sidecar_setting_reaches_mitmdump(tmp_path: Path) -> None:
    """Asserted against the real argv builder: a setting the sidecar never passes to mitmdump
    would leave the probe silently back on the eager default."""
    from bellwether.capture import CredentialBroker, MitmproxySidecar
    from bellwether.determinism import SeededRng

    sidecar = MitmproxySidecar(
        image="img",
        network="net",
        broker=CredentialBroker.for_run({}, {}, rng=SeededRng(1, "probe")),
        provider_of_host={},
        shared_dir=tmp_path,
        extra_settings=PROBE_SIDECAR_SETTINGS,
    )
    argv = sidecar.sidecar_argv("bw-proxy-probe", PurePosixPath("/shared/config.json"))
    assert "connection_strategy=lazy" in argv
    # Emitted as a --set pair, after the built-in ones.
    assert argv[argv.index("connection_strategy=lazy") - 1] == "--set"


def test_a_run_gets_no_extra_mitmdump_settings(tmp_path: Path) -> None:
    """The probe's setting must not reach an evaluation: a proxy that behaved differently would
    change what a trace means."""
    from bellwether.cli.proxy_run import SidecarProxyProvider

    assert SidecarProxyProvider.__dataclass_fields__["extra_settings"].default_factory() == {}


def test_the_probe_client_exits_non_zero_when_the_request_fails() -> None:
    """A client that always exits 0 makes the inconclusive message read "client exit 0" whether
    it ran or not — the uninformative signal that hid the eager-strategy failure in the first
    CI run."""
    assert "sys.exit(1)" in PROBE_CLIENT_SOURCE
