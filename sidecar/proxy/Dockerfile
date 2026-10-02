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

# Every Python package the image runs is hash-locked: requirements.txt is the whole closure —
# mitmproxy, Bellwether's runtime dependencies and the build backend — compiled from
# requirements.in with `--generate-hashes`, so what is reviewed is exactly what runs, the
# discipline uv.lock gives the main package. `--require-hashes` makes pip refuse any file whose
# digest is not recorded and any dependency the lock does not pin; `--only-binary :all:` refuses
# an sdist, whose build backend pip would fetch unhashed into an isolated environment.
COPY sidecar/proxy/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r /app/requirements.txt

# Install Bellwether so the addon can import the decision core (decide_request, the broker, the
# canonicaliser). Only the package metadata and source are copied — never the venv, tests, or git
# tree — so the build context stays small and reproducible. It is built offline (`--no-index`)
# against the locked hatchling (`--no-build-isolation`) and adds nothing (`--no-deps`): every
# dependency came from the lock above, and `pip check` fails the build if the lock fell short.
COPY pyproject.toml README.md LICENSE NOTICE /app/
COPY src /app/src
RUN pip install --no-cache-dir --no-index --no-deps --no-build-isolation /app && pip check

# The mitmdump entry, at the fixed path the launcher references (capture.sidecar.SIDECAR_ENTRY_PATH).
COPY sidecar/proxy/proxy_entry.py /opt/bw/proxy_entry.py
