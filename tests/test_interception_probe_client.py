"""The probe client, run for real against an intercepting proxy (§9.2).

The client is the part of the probe CI cannot check cheaply — the container proof needs the
sidecar image — and it is also the part that was wrong twice. The first cut hard-coded
``python3``, which the shipped ``claude-code`` sandbox image does not have; it carries ``node``
and ``sh``. So the client is exercised here against a **real** proxy: a socket server that
speaks ``CONNECT`` and then presents a self-signed certificate, which is exactly the shape
mitmproxy presents.

Both cases are covered, because a client that cannot fail establishes nothing:

- with the certificate in ``NODE_EXTRA_CA_CERTS``, the tunnel and the handshake complete;
- without it, the client refuses, and its wording is one ``interpret_interception_probe``
  recognises as a rejected CA rather than as an inconclusive shrug.

That second assertion is the one that keeps the interpreter honest: Node reports OpenSSL error
*codes*, not the prose OpenSSL and Python produce, so a marker list written against Python
alone would read every real Node rejection as "nothing established".
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from bellwether.capture import interpret_interception_probe
from bellwether.cli.interception_probe import PROBE_CLIENT_NODE, PROBE_HOST

_MISSING = [name for name in ("node", "openssl") if shutil.which(name) is None]
pytestmark = pytest.mark.skipif(bool(_MISSING), reason=f"not on PATH: {', '.join(_MISSING)}")


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    """A certificate for the probe host, made the way mitmproxy makes one: self-signed.

    Minted with the ``openssl`` binary rather than a Python library, because the point of this
    module is to run the real client against a real handshake and adding a dependency to do it
    would be the tail wagging the dog. The subject alternative name matters — Node checks it,
    and a certificate without one is rejected for a reason that has nothing to do with trust.
    """
    cert_path = tmp_path / "ca.pem"
    key_path = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            f"/CN={PROBE_HOST}",
            "-addext",
            f"subjectAltName=DNS:{PROBE_HOST}",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return cert_path, key_path


class _InterceptingProxy:
    """Accepts one CONNECT, then presents ``cert`` — what the sandbox has to trust."""

    def __init__(self, cert: Path, key: Path) -> None:
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        #: Set when a client completed the TLS handshake — the proxy's "recorded flow".
        self.handshake_completed = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:  # pragma: no cover - closed during teardown
            return
        with conn:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk
            if not request.startswith(b"CONNECT"):
                return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            try:
                with self.context.wrap_socket(conn, server_side=True) as tls_conn:
                    self.handshake_completed = True
                    tls_conn.recv(4096)
                    tls_conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            except ssl.SSLError:
                # The client refused the certificate: no flow, which is the point.
                return

    def __enter__(self) -> _InterceptingProxy:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.close()
        self.thread.join(timeout=5)


def _run_client(tmp_path: Path, *, port: int, ca: Path | None) -> subprocess.CompletedProcess[str]:
    script = tmp_path / "client.js"
    script.write_text(PROBE_CLIENT_NODE, encoding="utf-8")
    env = {
        "PATH": os.environ["PATH"],
        "HTTPS_PROXY": f"http://127.0.0.1:{port}",
        "BW_PROBE_HOST": PROBE_HOST,
    }
    if ca is not None:
        env["NODE_EXTRA_CA_CERTS"] = str(ca)
    return subprocess.run(
        ["node", str(script)], env=env, capture_output=True, text=True, timeout=60, check=False
    )


def test_the_node_client_tunnels_and_completes_the_handshake_when_the_ca_is_trusted(
    tmp_path: Path,
) -> None:
    """The shipped sandbox image carries node and nothing else, and Node ignores the system
    trust store — which is why §9.2 calls NODE_EXTRA_CA_CERTS not optional. This is that path,
    run for real."""
    cert, key = _self_signed(tmp_path)
    with _InterceptingProxy(cert, key) as proxy:
        completed = _run_client(tmp_path, port=proxy.port, ca=cert)

    assert proxy.handshake_completed, f"no handshake; client said: {completed.stderr}"
    probe = interpret_interception_probe(
        PROBE_HOST,
        [PROBE_HOST] if proxy.handshake_completed else [],
        exit_code=completed.returncode,
        stderr=completed.stderr,
    )
    assert probe.confirmed


def test_without_the_ca_the_node_client_refuses_and_the_interpreter_understands_it(
    tmp_path: Path,
) -> None:
    """The assertion that keeps the interpreter honest. Node reports OpenSSL error *codes*, not
    the prose Python produces, so a marker list written against Python alone would read a real
    Node rejection as "nothing established" — turning the one critical outcome into a shrug."""
    cert, key = _self_signed(tmp_path)
    with _InterceptingProxy(cert, key) as proxy:
        completed = _run_client(tmp_path, port=proxy.port, ca=None)

    assert not proxy.handshake_completed
    assert completed.returncode != 0, "a client that cannot fail establishes nothing"

    probe = interpret_interception_probe(
        PROBE_HOST, [], exit_code=completed.returncode, stderr=completed.stderr
    )
    assert probe.ca_rejected, (
        "the interpreter did not recognise node's rejection wording — "
        f"stderr was: {completed.stderr!r}"
    )
    assert not probe.inconclusive
