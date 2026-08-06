"""The mitmdump entry point for the recording-proxy sidecar image (§10.5).

``mitmdump -s /opt/bw/proxy_entry.py`` loads this; mitmproxy discovers the module-level ``addons``
list. All the logic lives in :mod:`bellwether.capture.sidecar_entry` (installed in the image and
unit-tested without mitmproxy); this file is only the thin binding that reads the run's config from
the environment and hands mitmproxy the addon, kept separate so the launcher can reference it at a
fixed path rather than a site-packages location.
"""

from bellwether.capture.sidecar_entry import load_addon_from_env

addons = [load_addon_from_env()]
