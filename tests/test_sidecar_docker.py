"""WP-13 done-when: the recording proxy, stood up for real (§10.5, §3.3).

**CI-only.** Building the image and routing between containers needs the public registries and
container networking the restricted build environment blocks, so this is gated on ``CI`` and skips
locally with a stated reason — the same honesty the ``docker``-mark skips carry.

Two tests, in increasing depth:

- **smoke**: the image builds and ``mitmdump`` loads our addon (the empty flow log appears). Proves
  Bellwether imports in the mitmproxy runtime and the inside-the-container half runs.
- **interception**: a client container sends the *scoped* token through the proxy on three legs.
  A permitted model-API call **over https** (a peer named as the provider) is forwarded with the
  **real key injected on the wire**; the same permitted host **over plaintext** is forwarded with
  the scoped token left in place, because §10.5.1 does not write a real credential onto an
  ``http://`` request; a denied host is **blocked** with a 403 the client sees. The flow log
  records all three while holding **neither the real key nor the scoped token**. This is the
  §3.3/§10.5 done-when: the container never holds the real key, yet the provider receives it, and
  the artifact is clean.

  The https leg is the one production uses, and until an independent review found the
  `pretty_host` defect this test only ever exercised plaintext — so the sole container-level proof
  of injection was taken against a scheme no real run makes, and the rule that a plaintext request
  keeps its scoped token had no proof at all. The peer therefore serves both: TLS on 443 with a
  self-signed certificate it generates at start-up, and plain HTTP on 80.

The topology avoids needing real DNS or internet: the "provider" is a peer container, named as the
provider endpoint, so docker's embedded DNS resolves it and classification is plain string matching.
The denied host is blocked *before* any forward, so it needs no resolution either. On any failure the
sidecar, peer, and client outputs are dumped into the assertion so a remote failure is diagnosable.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from bellwether.capture import (
    CapLedger,
    CredentialBroker,
    EgressAllowlist,
    MitmproxySidecar,
)
from bellwether.capture.proxy_addon import flow_record_line
from bellwether.determinism import SeededRng
from bellwether.errors import BellwetherError

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not os.environ.get("CI"),
        reason="the sidecar image build + container networking need open egress; CI only",
    ),
]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_IMAGE_TAG = "bw-proxy-sidecar:test"
_REAL_KEY = "sk-real-value-for-the-sidecar"
_PROVIDER_HOST = "provider-peer"  # a container name, used as the provider endpoint


def _daemon_available() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    return probe.returncode == 0


@pytest.fixture(scope="module")
def sidecar_image() -> str:
    """Build the sidecar image once. A build failure fails loudly — it is the point of the job."""
    if not _daemon_available():
        pytest.skip("no Docker daemon")
    build = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(_REPO_ROOT / "sidecar" / "proxy" / "Dockerfile"),
            "-t",
            _IMAGE_TAG,
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.fail(
            "sidecar image build failed:\n"
            f"--- stdout ---\n{build.stdout[-4000:]}\n--- stderr ---\n{build.stderr[-4000:]}"
        )
    return _IMAGE_TAG


def _broker() -> CredentialBroker:
    return CredentialBroker.for_run(
        {"anthropic": "ANTHROPIC_API_KEY"},
        {"ANTHROPIC_API_KEY": _REAL_KEY},
        rng=SeededRng(1, "cred"),
    )


# ---------------------------------------------------------------------------
# smoke — the image builds and the addon loads
# ---------------------------------------------------------------------------


def test_the_image_builds_and_mitmdump_loads_the_addon(sidecar_image: str, tmp_path: Path) -> None:
    """The empty flow log appearing is proof mitmdump came up and registered our addon."""
    run_id = f"smoke-{os.getpid()}"
    sidecar = MitmproxySidecar(
        image=sidecar_image,
        network="bridge",  # smoke needs no name resolution
        broker=_broker(),
        provider_of_host={_PROVIDER_HOST: "anthropic"},
        shared_dir=tmp_path / "shared",
        ready_timeout=60.0,
    )
    subprocess.run(["docker", "rm", "-f", f"bw-proxy-{run_id}"], capture_output=True, text=True)
    try:
        sidecar.start(
            run_id,
            allowlist=EgressAllowlist(
                provider_endpoints=frozenset({_PROVIDER_HOST}), infrastructure_endpoints=frozenset()
            ),
            caps=CapLedger(max_requests=10, max_request_bytes=100_000),
        )
    except BellwetherError as exc:
        logs = subprocess.run(
            ["docker", "logs", f"bw-proxy-{run_id}"], capture_output=True, text=True
        )
        pytest.fail(f"{exc}\n--- container logs ---\n{logs.stdout}\n{logs.stderr}")
    try:
        assert sidecar.flows() == []
        assert sidecar.proxy_url() == f"http://bw-proxy-{run_id}:8080"
    finally:
        sidecar.stop()


# ---------------------------------------------------------------------------
# interception — inject on forward, block on deny, no credential in the artifact
# ---------------------------------------------------------------------------

# The peer echoes the request headers it received, over **both** schemes: 443 with TLS, 80
# without. Two legs, because the two are now different security decisions — §10.5.1 injects the
# real credential only over https, since a key written onto a plaintext request is readable by
# anything on the path. The earlier version of this test served plaintext only, so the one
# container-level proof of injection was taken against a scheme production never uses, and the
# rule that a plaintext request keeps the scoped token had no proof at all.
#
# The TLS certificate is self-signed and generated at start-up (`cryptography` is already in the
# image as a mitmproxy dependency). The proxy accepts it because this test passes
# `ssl_insecure=true`, which is a test-only setting: a real run verifies its upstream.
_PEER_SERVER = (
    "import http.server, ssl, tempfile, threading, datetime\n"
    "from cryptography import x509\n"
    "from cryptography.x509.oid import NameOID\n"
    "from cryptography.hazmat.primitives import hashes, serialization\n"
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'provider-peer')])\n"
    "now = datetime.datetime.now(datetime.timezone.utc)\n"
    "cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)\n"
    "    .public_key(key.public_key()).serial_number(x509.random_serial_number())\n"
    "    .not_valid_before(now - datetime.timedelta(days=1))\n"
    "    .not_valid_after(now + datetime.timedelta(days=1))\n"
    "    .add_extension(x509.SubjectAlternativeName([x509.DNSName('provider-peer')]), False)\n"
    "    .sign(key, hashes.SHA256()))\n"
    "pem = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)\n"
    "pem.write(cert.public_bytes(serialization.Encoding.PEM))\n"
    "pem.write(key.private_bytes(serialization.Encoding.PEM,\n"
    "    serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))\n"
    "pem.close()\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        body = '\\n'.join(f'{k}: {v}' for k, v in self.headers.items()).encode()\n"
    "        self.send_response(200)\n"
    "        self.send_header('Content-Type', 'text/plain')\n"
    "        self.send_header('Content-Length', str(len(body)))\n"
    "        self.end_headers()\n"
    "        self.wfile.write(body)\n"
    "    def log_message(self, *a):\n"
    "        pass\n"
    "def serve_tls():\n"
    "    srv = http.server.HTTPServer(('0.0.0.0', 443), H)\n"
    "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
    "    ctx.load_cert_chain(pem.name)\n"
    "    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)\n"
    "    srv.serve_forever()\n"
    "threading.Thread(target=serve_tls, daemon=True).start()\n"
    "http.server.HTTPServer(('0.0.0.0', 80), H).serve_forever()\n"
)

# Three requests through the proxy, all carrying the *scoped* token:
#   1. https://provider-peer/  — permitted, model_api, and the leg §10.5.1 injects on;
#   2. http://provider-peer/   — permitted and forwarded, but plaintext, so the real key must
#      stay behind and the scoped token must go out unchanged;
#   3. http://evil.example.com/ — denied by the default-deny allowlist.
# The client does not verify the proxy's leaf certificate: mitmproxy mints it from a CA generated
# inside the sidecar, and distributing that CA is §9.2's job, tested elsewhere. What this test is
# about is which credential reaches the peer.
_CLIENT = (
    "import urllib.request, urllib.error, os, ssl, time\n"
    "proxy = os.environ['PROXY_URL']\n"
    "ctx = ssl._create_unverified_context()\n"
    "op = urllib.request.build_opener(\n"
    "    urllib.request.ProxyHandler({'http': proxy, 'https': proxy}),\n"
    "    urllib.request.HTTPSHandler(context=ctx),\n"
    ")\n"
    "token = os.environ['ANTHROPIC_API_KEY']\n"
    "def fetch(url, label):\n"
    "    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token})\n"
    # Retry: the peer's servers may still be binding when the client starts.
    "    last = None\n"
    "    for attempt in range(15):\n"
    "        try:\n"
    "            r = op.open(req, timeout=25)\n"
    "            print(label + '_STATUS', r.status)\n"
    "            print(label + '_BEGIN'); print(r.read().decode()); print(label + '_END')\n"
    "            return\n"
    "        except urllib.error.HTTPError as e:\n"
    "            print(label + '_STATUS', e.code); return\n"
    "        except Exception as e:\n"
    "            last = e; time.sleep(1)\n"
    "    print(label + '_ERR', repr(last))\n"
    "fetch('https://provider-peer/', 'TLS')\n"
    "fetch('http://provider-peer/', 'PLAIN')\n"
    "fetch('http://evil.example.com/', 'DENIED')\n"
    # Two paths that reached a destination without the request hook ever deciding them (§10.5.0,
    # spec-notes): a CONNECT tunnel, answered before any request inside it exists, and a body that
    # does not decode under its Content-Encoding, which made the hook raise and mitmproxy forward.
    "import socket\n"
    "host, port = proxy.rsplit('//', 1)[-1].rsplit(':', 1)\n"
    "def raw(payload, label):\n"
    "    s = socket.create_connection((host, int(port)), timeout=25)\n"
    "    s.sendall(payload)\n"
    "    print(label + '_STATUS', s.recv(200).split(b' ')[1].decode())\n"
    "    s.close()\n"
    "raw(b'CONNECT evil.example.com:443 HTTP/1.1\\r\\nHost: evil.example.com:443\\r\\n\\r\\n', "
    "'TUNNEL')\n"
    "body = b'not-gzip-at-all'\n"
    "raw(b'POST http://evil.example.com/x HTTP/1.1\\r\\nHost: evil.example.com\\r\\n'\n"
    "    b'Content-Encoding: gzip\\r\\nContent-Length: ' + str(len(body)).encode() + "
    "b'\\r\\n\\r\\n' + body, 'UNDECODABLE')\n"
)


@pytest.fixture
def network() -> Iterator[str]:
    """A user-defined internal bridge — internal so it also exercises §3.3 invariant 3, and
    user-defined so docker's embedded DNS resolves the peer and proxy by name."""
    name = f"bw-net-{os.getpid()}"
    subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True)
    created = subprocess.run(
        ["docker", "network", "create", "--internal", "--driver", "bridge", name],
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.fail(f"could not create test network: {created.stderr}")
    try:
        yield name
    finally:
        subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True)


def test_a_real_run_injects_on_forward_blocks_on_deny_and_leaks_nothing(
    sidecar_image: str, network: str, tmp_path: Path
) -> None:
    broker = _broker()
    scoped_token = broker.sandbox_token("anthropic")
    run_id = f"icept-{os.getpid()}"
    proxy_name = f"bw-proxy-{run_id}"

    sidecar = MitmproxySidecar(
        image=sidecar_image,
        network=network,
        broker=broker,
        provider_of_host={_PROVIDER_HOST: "anthropic"},
        shared_dir=tmp_path / "shared",
        ready_timeout=60.0,
        # Test-only: the peer's certificate is self-signed, so the proxy's *upstream* leg would
        # otherwise refuse it. A real run verifies its upstream, which is why this setting exists
        # on the launcher rather than in the image.
        extra_settings={"ssl_insecure": "true"},
    )

    # docker forwards the real key into the sidecar from the launcher's own env (`-e KEY`, no value).
    os.environ["ANTHROPIC_API_KEY"] = _REAL_KEY
    for name in (_PROVIDER_HOST, proxy_name):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)

    peer_started = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            _PROVIDER_HOST,
            "--network",
            network,
            sidecar_image,
            "python3",
            "-c",
            _PEER_SERVER,
        ],
        capture_output=True,
        text=True,
    )
    if peer_started.returncode != 0:
        pytest.fail(f"could not start the provider peer: {peer_started.stderr}")

    try:
        try:
            sidecar.start(
                run_id,
                allowlist=EgressAllowlist(
                    provider_endpoints=frozenset({_PROVIDER_HOST}),
                    infrastructure_endpoints=frozenset(),
                ),
                caps=CapLedger(max_requests=10, max_request_bytes=1_000_000),
            )
        except BellwetherError as exc:
            pytest.fail(f"{exc}\n{_diagnostics(proxy_name)}")

        client = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                "-e",
                f"PROXY_URL={sidecar.proxy_url()}",
                "-e",
                f"ANTHROPIC_API_KEY={scoped_token}",
                sidecar_image,
                "python3",
                "-c",
                _CLIENT,
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        out = client.stdout
        context = (
            f"client stdout:\n{out}\nclient stderr:\n{client.stderr}\n{_diagnostics(proxy_name)}"
        )

        def echo_of(label: str) -> str:
            if f"{label}_BEGIN" not in out:
                return ""
            return out.split(f"{label}_BEGIN", 1)[-1].split(f"{label}_END", 1)[0]

        # (1) The permitted **https** call reached the peer, and the peer saw the REAL key —
        # injection happened on the wire — while the scoped token did not survive.
        assert "TLS_STATUS 200" in out, context
        tls_echo = echo_of("TLS")
        assert _REAL_KEY in tls_echo, f"real key not injected upstream\n{context}"
        assert scoped_token not in tls_echo, f"scoped token leaked past the proxy\n{context}"

        # (2) The same permitted host over **plaintext** is forwarded — the allowlist decides the
        # host, not the scheme — but keeps the scoped token. §10.5.1: a real credential written
        # onto an http:// request is readable by anything on the path, and a provider genuinely
        # reachable over plaintext is not one this proxy should be feeding a key to.
        assert "PLAIN_STATUS 200" in out, context
        plain_echo = echo_of("PLAIN")
        assert _REAL_KEY not in plain_echo, f"real key injected onto a plaintext request\n{context}"
        assert f"Bearer {scoped_token}" in plain_echo, context

        # (3) The denied host was blocked with a real 403 the client saw.
        assert "DENIED_STATUS 403" in out, context

        # The flow log recorded both, and holds neither credential.
        flows = sidecar.flows()
        model_flows = [f for f in flows if f.host == _PROVIDER_HOST and not f.blocked]
        blocked = [f for f in flows if "evil.example.com" in f.host and f.blocked]
        assert model_flows, f"no forwarded model flow recorded\n{context}"
        assert model_flows[0].egress_class == "model_api", context
        assert blocked, f"no blocked flow recorded\n{context}"
        # (4) A CONNECT to a denied host is refused before it is dialled, and recorded. Without
        # the http_connect gate mitmproxy answers 200 and relays whatever the tunnel carries.
        assert "TUNNEL_STATUS 403" in out, context
        assert any(f.method == "CONNECT" and f.host == "evil.example.com" for f in blocked), context
        # (5) A request the hook cannot decode is refused and recorded, never forwarded undecided.
        assert "UNDECODABLE_STATUS 502" in out, context
        assert any("request hook failed" in f.block_reason for f in blocked), context
        log_text = "\n".join(flow_record_line(f) for f in flows)
        assert _REAL_KEY not in log_text, f"real key leaked into the flow log\n{context}"
        assert scoped_token not in log_text, f"scoped token leaked into the flow log\n{context}"
        assert not broker.leaks_a_real_key(log_text)
    finally:
        subprocess.run(["docker", "rm", "-f", _PROVIDER_HOST], capture_output=True, text=True)
        sidecar.stop()
        os.environ.pop("ANTHROPIC_API_KEY", None)


def _diagnostics(proxy_name: str) -> str:
    logs = subprocess.run(["docker", "logs", proxy_name], capture_output=True, text=True)
    return f"--- sidecar logs ---\n{logs.stdout[-3000:]}\n{logs.stderr[-3000:]}"
