"""WP-14's live half, offline: what a CA-in-the-loop probe establishes (§9.2, §20).

The dangerous state this exists for: a container that rejects the proxy's certificate makes no
observable egress, so the run produces a zero-egress trace that reads as a skill which never
touched the network. Doctor used to report the proxy as *configured* and stop there. These
tests pin the decision the probe feeds, and the command it runs; the container half is
`test_interception_probe_docker.py`.
"""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path, PurePosixPath
from typing import ClassVar

import pytest

from bellwether.capture import interpret_interception_probe
from bellwether.cli.interception_probe import (
    PROBE_CLIENT_NODE,
    PROBE_CLIENT_PYTHON,
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
    assert argv[-3:-1] == ["sh", "-c"]
    assert "command -v node" in argv[-1] and "urllib.request" in argv[-1]


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


def test_every_probe_client_exits_non_zero_when_the_request_fails() -> None:
    """A client that always exits 0 makes the inconclusive message read "client exit 0" whether
    it ran or not — the uninformative signal that hid the eager-strategy failure in the first
    CI run. Both interpreters, because the dispatcher picks one and the other is then the only
    thing standing between a broken trust chain and a green row."""
    assert "sys.exit(1)" in PROBE_CLIENT_PYTHON
    assert "process.exit(1)" in PROBE_CLIENT_NODE


def test_the_probe_client_runs_on_an_image_carrying_only_node() -> None:
    """The finding that made this a dispatcher: the shipped ``claude-code`` sandbox image has
    no ``python3``, no ``curl``, no ``openssl`` — ``node`` and ``sh``. A hard-coded ``python3``
    client could only ever return *inconclusive* on the one image that matters."""
    from bellwether.cli.interception_probe import probe_client_command

    command = probe_client_command()
    assert "command -v node" in command
    # Node is tried first, so an image carrying both still exercises NODE_EXTRA_CA_CERTS —
    # the §9.2 mechanism spec-notes calls not optional, and the one most likely to be missing.
    assert command.index("command -v node") < command.index("command -v python3")


def test_an_image_with_no_interpreter_is_inconclusive_not_a_pass() -> None:
    """Exit 127 is "we could not tell", never "the CA is trusted": an image that cannot make a
    request says nothing about its trust store, and saying so is the honest answer."""
    from bellwether.cli.interception_probe import probe_client_command

    completed = subprocess.run(
        ["/bin/sh", "-c", probe_client_command()],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={"PATH": "/nonexistent-bin"},
    )
    assert completed.returncode == 127
    probe = interpret_interception_probe(
        PROBE_HOST, [], exit_code=completed.returncode, stderr=completed.stderr
    )
    assert probe.inconclusive and not probe.confirmed and not probe.ca_rejected


# ---------------------------------------------------------------------------
# Review fixes: what the probe actually probes, and how doctor survives it
# ---------------------------------------------------------------------------


def _doctor_config(tmp_path: Path):  # type: ignore[no-untyped-def]
    from bellwether.config.models.config import Config

    return Config.model_validate(
        {
            "apiVersion": "bellwether/v1",
            "kind": "Config",
            "sandbox": {"image": "sandbox@sha256:" + "5" * 64},
            "egress": {"image": "sidecar@sha256:" + "6" * 64},
        }
    )


def test_doctor_probes_the_sandbox_image_not_the_sidecar(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """A review finding, and the sharpest kind: the row said "the CA is trusted and egress is
    observed" while the client was the *sidecar* image. The container that has to trust the CA
    is the sandbox — that is what a run puts on the internal bridge — so probing the sidecar
    rendered an `ok` about a container no evaluation uses, and could not fail for the one state
    the probe exists to rule out."""
    app_module = importlib.import_module("bellwether.cli.app")
    probe_module = importlib.import_module("bellwether.cli.interception_probe")
    run_module = importlib.import_module("bellwether.cli.run")

    seen: dict[str, object] = {}

    def _fake_probe(provider, *, client_image, **kwargs):  # type: ignore[no-untyped-def]
        seen["client_image"] = client_image
        return interpret_interception_probe(PROBE_HOST, [PROBE_HOST], exit_code=1)

    monkeypatch.setattr(run_module, "build_proxy_provider", lambda *_a, **_k: object())
    monkeypatch.setattr(probe_module, "run_interception_probe", _fake_probe)

    row = app_module._interception_probe_check(_doctor_config(tmp_path))

    assert seen["client_image"] == "sandbox@sha256:" + "5" * 64
    assert row["status"] == "ok"


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(2, "No such file or directory: 'docker'"),
        subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=120.0),
    ],
)
def test_doctor_survives_a_probe_that_cannot_run(monkeypatch, tmp_path: Path, error) -> None:  # type: ignore[no-untyped-def]
    """A missing docker binary, or a pull that outruns the client timeout, says nothing about
    the CA — and must not abort doctor with a traceback in place of its remaining rows."""
    app_module = importlib.import_module("bellwether.cli.app")
    probe_module = importlib.import_module("bellwether.cli.interception_probe")
    run_module = importlib.import_module("bellwether.cli.run")

    def _raise(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise error

    monkeypatch.setattr(run_module, "build_proxy_provider", lambda *_a, **_k: object())
    monkeypatch.setattr(probe_module, "run_interception_probe", _raise)

    row = app_module._interception_probe_check(_doctor_config(tmp_path))

    # Reported, not raised — and reported as "not probed", never as a pass.
    assert row["status"] == "warn"
    assert row["detail"].startswith("not probed:")
    assert type(error).__name__ in row["detail"]


def test_doctor_says_so_when_no_proxy_is_wired(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A first-light configuration has no egress plane at all, so there is nothing to establish
    — a warn that says why, not a pass and not a failure."""
    app_module = importlib.import_module("bellwether.cli.app")
    run_module = importlib.import_module("bellwether.cli.run")
    from bellwether.config.models.config import Config

    monkeypatch.setattr(run_module, "build_proxy_provider", lambda *_a, **_k: None)
    networkless = Config.model_validate(
        {
            "apiVersion": "bellwether/v1",
            "kind": "Config",
            "sandbox": {"image": "sandbox@sha256:" + "5" * 64},
        }
    )
    row = app_module._interception_probe_check(networkless)
    assert row["status"] == "warn"
    assert "egress.image is empty" in row["detail"]


def test_an_overridden_probe_host_reaches_the_client(tmp_path: Path) -> None:
    """`probe_host` was threaded into the *interpreter* but not into the command, so a caller
    that overrode it got a client still asking for the default — and a probe guaranteed to
    report "inconclusive" however well the CA was trusted."""
    argv = probe_argv(
        image="img",
        network="net",
        environment={"HTTPS_PROXY": "http://p:8080"},
        ca_host_path=Path("/tmp/ca.pem"),
        probe_host="somewhere-else.invalid",
    )
    assert "BW_PROBE_HOST=somewhere-else.invalid" in argv
    assert f"BW_PROBE_HOST={PROBE_HOST}" not in argv


def test_the_probe_container_is_named_so_a_timed_out_client_can_be_removed() -> None:
    """A client that outlives its runner stays attached to the sandbox bridge, and the bridge
    then refuses to be removed — so the module's "never leaks a bridge or a container" needs a
    handle on the container, not just on the `docker run` process."""
    argv = probe_argv(
        image="img",
        network="net",
        environment={},
        ca_host_path=Path("/tmp/ca.pem"),
        container_name="bw-interception-probe-abc123",
    )
    assert argv[argv.index("bw-interception-probe-abc123") - 1] == "--name"


def test_the_probe_removes_its_client_container_even_when_the_run_times_out(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Asserted through the real standup path, because the leak is in its ordering: the client
    has to be removed *before* the proxy's bridge is, or the bridge removal is what fails.

    ``subprocess.run`` kills the ``docker run`` process on timeout and leaves the container it
    started running, attached to the sandbox bridge. Without the removal, a probe that timed
    out took the bridge with it — the one thing the module says it never does.
    """
    probe_module = importlib.import_module("bellwether.cli.interception_probe")
    order: list[str] = []

    class _TimesOut(probe_module.ProbeRunner):
        def run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(argv, self.timeout_seconds)

        def remove(self, container_name: str) -> None:
            order.append("remove")

    class _Proxy:
        ca_host_path = Path("/tmp/ca.pem")

        def sandbox_network(self) -> str:
            return "bw-internal"

        def sandbox_env(self) -> dict[str, str]:
            return {}

        def flows(self) -> list[object]:
            return []

        def close(self) -> None:
            order.append("proxy-close")

    class _Provider:
        extra_settings: ClassVar[dict[str, str]] = {}

        def open(self, _run_id: str, *, shared_dir: Path) -> _Proxy:
            return _Proxy()

    # The provider is a stand-in, so the dataclass rewrite the probe applies to a real
    # `SidecarProxyProvider` has nothing to rewrite; the substitution under test is the
    # teardown order, not the settings.
    monkeypatch.setattr(probe_module, "replace", lambda provider, **_kwargs: provider)

    with pytest.raises(subprocess.TimeoutExpired):
        probe_module.run_interception_probe(_Provider(), client_image="img", runner=_TimesOut())

    assert order == ["remove", "proxy-close"]


# ---------------------------------------------------------------------------
# What counts as confirmation, read at the wiring (§9.2, §10.5.0)
#
# The proxy now gates a CONNECT on the allowlist *before* any TLS handshake, and records a refused
# one. The probe used to count any recorded probe host as confirmation and to keep its host off the
# allowlist, so on CI a client with no CA at all "confirmed" interception off the CONNECT record.
# ---------------------------------------------------------------------------


def _probe_with_flows(monkeypatch, flows: list[object]) -> tuple[object, dict[str, object]]:  # type: ignore[no-untyped-def]
    probe_module = importlib.import_module("bellwether.cli.interception_probe")
    captured: dict[str, object] = {}

    class _Runs(probe_module.ProbeRunner):
        def run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 1, "", "")

        def remove(self, container_name: str) -> None:
            pass

    class _Proxy:
        ca_host_path = Path("/tmp/ca.pem")

        def sandbox_network(self) -> str:
            return "bw-internal"

        def sandbox_env(self) -> dict[str, str]:
            return {}

        def flows(self) -> list[object]:
            return flows

        def close(self) -> None:
            pass

    class _Provider:
        extra_settings: ClassVar[dict[str, str]] = {}

        def open(self, _run_id: str, *, shared_dir: Path) -> _Proxy:
            return _Proxy()

    def _capture(provider, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return provider

    monkeypatch.setattr(probe_module, "replace", _capture)
    probe = probe_module.run_interception_probe(_Provider(), client_image="img", runner=_Runs())
    return probe, captured


def _flow(method: str, scheme: str, *, blocked: bool) -> object:
    from bellwether.capture.egress import EgressFlow

    return EgressFlow(
        ts="t",
        method=method,
        scheme=scheme,
        host=PROBE_HOST,
        port=443,
        path="/bellwether-probe" if scheme == "https" else "",
        egress_class="skill_attributed",
        blocked=blocked,
    )


def test_a_recorded_connect_alone_does_not_confirm_interception(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A CONNECT is recorded before any handshake, so it says nothing about the CA."""
    probe, _ = _probe_with_flows(monkeypatch, [_flow("CONNECT", "connect", blocked=True)])
    assert not probe.confirmed  # type: ignore[attr-defined]


def test_a_request_recorded_inside_tls_confirms_interception(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    probe, _ = _probe_with_flows(monkeypatch, [_flow("GET", "https", blocked=False)])
    assert probe.confirmed  # type: ignore[attr-defined]


def test_the_probes_proxy_lets_the_probe_host_tunnel_and_nothing_else(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Its CONNECT must be let through for the client to reach the handshake at all; the name is
    unresolvable, and no other host is widened."""
    _, captured = _probe_with_flows(monkeypatch, [])
    allowlist = captured["allowlist"]
    assert allowlist.permits(PROBE_HOST)  # type: ignore[attr-defined]
    assert not allowlist.permits("example.com")  # type: ignore[attr-defined]
    assert PROBE_HOST.endswith(".invalid")
