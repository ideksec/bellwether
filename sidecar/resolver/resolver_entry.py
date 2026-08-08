"""The entry point for the controlled-resolver sidecar image (§10.6).

``python /opt/bw/resolver_entry.py`` runs this. All the logic lives in
:mod:`bellwether.capture.resolver_entry` (installed in the image and unit-tested without dnslib);
this file is only the thin binding that reads the run's config from the environment, hands the
recording resolver to a dnslib UDP server, and serves until the container is stopped — kept
separate so the launcher can reference it at a fixed path rather than a site-packages location, the
same treatment the recording proxy's ``proxy_entry.py`` gets.

``DNSServer.start()`` blocks, serving UDP/53; the host stops the container to end the run. Binding
53 needs root, which the sidecar container has — it is host-controlled infrastructure, never the
observed sandbox.
"""

from bellwether.capture.resolver_entry import load_resolver_from_env


def main() -> None:
    from dnslib.server import DNSServer

    resolver = load_resolver_from_env()
    server = DNSServer(resolver, port=resolver_listen_port(), address="0.0.0.0")
    server.start()


def resolver_listen_port() -> int:
    """The UDP port the resolver binds — read from the same config the recorder loaded, so the
    launcher's ``listen_port`` and the server agree. Defaults to 53."""
    import json
    import os
    from pathlib import Path

    from bellwether.capture.resolver_entry import RESOLVER_CONFIG_ENV_VAR

    config_path = os.environ.get(RESOLVER_CONFIG_ENV_VAR)
    if not config_path:
        return 53
    payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
    port = payload.get("listen_port", 53)
    return int(port)


if __name__ == "__main__":
    main()
