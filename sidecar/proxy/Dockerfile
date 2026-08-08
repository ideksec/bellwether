# The recording-proxy sidecar (§10.5, §22). mitmproxy runs here, in its own container, so its
# pinned transitive dependencies never couple to Bellwether's resolved environment — the reason
# §10.5 mandates a sidecar over an in-process library. The host launcher (MitmproxySidecar) passes
# the full `mitmdump ... -s /opt/bw/proxy_entry.py` argv, so there is deliberately no ENTRYPOINT:
# the exact command stays recordable, the same reason the sandbox backend shells out explicitly.
#
# Base pinned by digest, not tag: a supply-chain tool that pulled a mutable base in its own image
# build would undermine its own thesis (tools/pin_lint.py enforces this). To update, query the
# registry for the new 3.12-slim manifest digest and replace it here.
FROM python:3.12-slim@sha256:646fb0bca3dd3ea1bcc6feb72c17ed16eed6e10cffc732fcc1478bd3e7f02d7b

# A pip constraint file bounds the sidecar's shared transitive deps so installing Bellwether
# cannot bump one out from under mitmproxy. Concretely: installing Bellwether resolved
# typing-extensions to 4.16.0, which breaks mitmproxy 12.2.3's `typing-extensions<=4.14`; the
# constraint holds it in mitmproxy's supported range for *every* install below. It is applied to
# both installs so the bound holds no matter which one would otherwise pull the newer version.
#
# This is a bounded stopgap, not the full pin. The complete fix is to hash-pin the sidecar's
# entire Python closure — `uv export` its locked requirements, then `pip install --require-hashes`
# — so what is reviewed is exactly what runs, the discipline uv.lock gives the main package. See
# sidecar/proxy/constraints.txt.
COPY sidecar/proxy/constraints.txt /app/constraints.txt

# mitmproxy pinned to an exact version: its addon API is not stable across majors (§22), so a
# floating version could silently break `request`/`response` hooks. Bump deliberately.
RUN pip install --no-cache-dir --constraint /app/constraints.txt mitmproxy==12.2.3

# Install Bellwether so the addon can import the decision core (decide_request, the broker, the
# canonicaliser). Only the package metadata and source are copied — never the venv, tests, or git
# tree — so the build context stays small and reproducible.
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir --constraint /app/constraints.txt /app

# The mitmdump entry, at the fixed path the launcher references (capture.sidecar.SIDECAR_ENTRY_PATH).
COPY sidecar/proxy/proxy_entry.py /opt/bw/proxy_entry.py
