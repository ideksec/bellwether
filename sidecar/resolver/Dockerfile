# The controlled-resolver sidecar (§10.6, §22). A small dnslib UDP/53 server runs here, in its own
# container, so its dependencies never couple to Bellwether's resolved environment — the same reason
# §10.5/§10.6 mandate a sidecar over an in-process library. The host launcher (DnsResolverSidecar)
# passes the full `python /opt/bw/resolver_entry.py` argv, so there is deliberately no ENTRYPOINT:
# the exact command stays recordable, the same reason the sandbox backend shells out explicitly.
#
# Base pinned by digest, not tag: a supply-chain tool that pulled a mutable base in its own image
# build would undermine its own thesis (tools/pin_lint.py enforces this). The digest matches the
# recording-proxy sidecar's base, so both sidecars share one reviewed image. To update, query the
# registry for the new 3.12-slim manifest digest and replace it here.
FROM python:3.12-slim@sha256:646fb0bca3dd3ea1bcc6feb72c17ed16eed6e10cffc732fcc1478bd3e7f02d7b

# Every Python package the image runs is hash-locked: requirements.txt is the whole closure —
# dnslib, Bellwether's runtime dependencies and the build backend — compiled from requirements.in
# with `--generate-hashes`, the same discipline as the recording-proxy sidecar. `--require-hashes`
# makes pip refuse any file whose digest is not recorded and any dependency the lock does not pin;
# `--only-binary :all:` refuses an sdist, whose build backend pip would fetch unhashed.
COPY sidecar/resolver/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r /app/requirements.txt

# Install Bellwether so the entry can import the resolver core (decide_query, the query serializer,
# load_resolver_from_env). Only the package metadata and source are copied — never the venv, tests,
# or git tree — so the build context stays small and reproducible. Built offline against the locked
# hatchling, adding no dependency of its own; `pip check` fails the build if the lock fell short.
COPY pyproject.toml README.md LICENSE NOTICE /app/
COPY src /app/src
RUN pip install --no-cache-dir --no-index --no-deps --no-build-isolation /app && pip check

# The resolver entry, at the fixed path the launcher references
# (capture.dns_sidecar.RESOLVER_ENTRY_PATH).
COPY sidecar/resolver/resolver_entry.py /opt/bw/resolver_entry.py
