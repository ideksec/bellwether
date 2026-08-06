"""WP-14: the proxy CA trust chain (§9.2).

The host-side core — the mechanism table, the install environment and commands, and the
interception-confirmation predicate doctor applies. The live half — doctor issuing a real
request from inside a container and checking the proxy recorded it — is the sidecar's job,
validated on CI; the decision it feeds is tested here. A silent interception failure yields
zero-egress traces that read as a clean skill, so this predicate is load-bearing.
"""

from __future__ import annotations

from bellwether.capture import (
    CA_MECHANISMS,
    DEFAULT_CA_CONTAINER_PATH,
    ca_trust_environment,
    interception_confirmed,
    system_store_install_commands,
)


def test_the_mechanism_table_covers_the_runtimes_that_ignore_the_system_store() -> None:
    """§9.2: Node reads a bundled CA list and ignores the store, so its env var must be
    present; certifi-based Python and curl likewise."""
    env_names = {m.name for m in CA_MECHANISMS if m.kind == "env"}
    assert {
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
    } <= env_names
    assert any(m.kind == "store" for m in CA_MECHANISMS)


def test_the_trust_environment_points_every_var_at_the_ca() -> None:
    env = ca_trust_environment("/etc/ssl/bw.pem")
    assert env["NODE_EXTRA_CA_CERTS"] == "/etc/ssl/bw.pem"
    assert env["REQUESTS_CA_BUNDLE"] == "/etc/ssl/bw.pem"
    assert env["SSL_CERT_FILE"] == "/etc/ssl/bw.pem"
    assert env["CURL_CA_BUNDLE"] == "/etc/ssl/bw.pem"
    # Only the env mechanisms appear here; the system store is a command, not a var.
    assert "system store" not in env


def test_the_default_ca_path_is_where_update_ca_certificates_looks() -> None:
    assert DEFAULT_CA_CONTAINER_PATH.startswith("/usr/local/share/ca-certificates/")
    assert DEFAULT_CA_CONTAINER_PATH.endswith(".crt")


def test_install_commands_copy_the_ca_and_refresh_the_store() -> None:
    commands = system_store_install_commands("/tmp/bw-ca.crt")
    assert commands[0][0] == "cp" and commands[0][1] == "/tmp/bw-ca.crt"
    assert commands[0][2] == DEFAULT_CA_CONTAINER_PATH
    assert ["update-ca-certificates"] in commands


def test_interception_is_confirmed_when_the_probe_host_was_recorded() -> None:
    assert interception_confirmed(["api.anthropic.com", "example.test"], "example.test")


def test_interception_is_not_confirmed_when_the_probe_is_absent() -> None:
    """The dangerous case: the proxy recorded nothing for the probe, so TLS interception
    silently failed — doctor must fail loudly on this."""
    assert not interception_confirmed(["api.anthropic.com"], "example.test")
    assert not interception_confirmed([], "example.test")


def test_confirmation_normalises_host_casing_and_trailing_dot() -> None:
    assert interception_confirmed(["Example.Test."], "example.test")
