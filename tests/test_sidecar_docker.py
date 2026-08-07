"""WP-13 done-when: the recording proxy, stood up for real (§10.5, §3.3).

**CI-only.** Building the image and routing between containers needs the public registries and
container networking the restricted build environment blocks, so this is gated on ``CI`` and skips
locally with a stated reason — the same honesty the ``docker``-mark skips carry.

Two tests, in increasing depth:

- **smoke**: the image builds and ``mitmdump`` loads our addon (the empty flow log appears). Proves
  Bellwether imports in the mitmproxy runtime and the inside-the-container half runs.
- **interception**: a client container sends the *scoped* token through the proxy. A permitted
  model-API call (a peer named as the provider) is forwarded with the **real key injected on the
  wire**, a denied host is **blocked** with a 403 the client sees, and the flow log records both
  while holding **neither the real key nor the scoped token**. This is the §3.3/§10.5 done-when:
  the container never holds the real key, yet the provider receives it, and the artifact is clean.

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

_PEER_SERVER = (
    "import http.server\n"
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
    "http.server.HTTPServer(('0.0.0.0', 80), H).serve_forever()\n"
)

_CLIENT = (
    "import urllib.request, urllib.error, os, time\n"
    "op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': os.environ['PROXY_URL']}))\n"
    "token = os.environ['ANTHROPIC_API_KEY']\n"
    "req = urllib.request.Request('http://provider-peer/', headers={'Authorization': 'Bearer ' + token})\n"
    # Retry the permitted call: the peer's HTTP server may still be binding when the client starts.
    "for attempt in range(15):\n"
    "    try:\n"
    "        r = op.open(req, timeout=25)\n"
    "        print('PERMITTED_STATUS', r.status)\n"
    "        print('ECHO_BEGIN'); print(r.read().decode()); print('ECHO_END')\n"
    "        break\n"
    "    except urllib.error.HTTPError as e:\n"
    "        print('PERMITTED_STATUS', e.code); break\n"
    "    except Exception as e:\n"
    "        last = e; time.sleep(1)\n"
    "else:\n"
    "    print('PERMITTED_ERR', repr(last))\n"
    "try:\n"
    "    r = op.open('http://evil.example.com/', timeout=25)\n"
    "    print('DENIED_STATUS', r.status)\n"
    "except urllib.error.HTTPError as e:\n"
    "    print('DENIED_STATUS', e.code)\n"
    "except Exception as e:\n"
    "    print('DENIED_ERR', repr(e))\n"
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

        # The permitted call reached the peer, and the peer saw the REAL key — injection happened
        # on the wire — while the scoped token did not survive (it was replaced).
        assert "PERMITTED_STATUS 200" in out, context
        echo = out.split("ECHO_BEGIN", 1)[-1].split("ECHO_END", 1)[0] if "ECHO_BEGIN" in out else ""
        assert _REAL_KEY in echo, f"real key not injected upstream\n{context}"
        assert scoped_token not in echo, f"scoped token leaked past the proxy\n{context}"

        # The denied host was blocked with a real 403 the client saw.
        assert "DENIED_STATUS 403" in out, context

        # The flow log recorded both, and holds neither credential.
        flows = sidecar.flows()
        model_flows = [f for f in flows if f.host == _PROVIDER_HOST and not f.blocked]
        blocked = [f for f in flows if "evil.example.com" in f.host and f.blocked]
        assert model_flows, f"no forwarded model flow recorded\n{context}"
        assert model_flows[0].egress_class == "model_api", context
        assert blocked, f"no blocked flow recorded\n{context}"
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
