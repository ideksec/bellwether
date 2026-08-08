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

# A pip constraint file bounds the sidecar's shared transitive deps so installing Bellwether cannot
# bump one out from under the pinned dnslib — the same bounded stopgap the recording proxy uses for
# mitmproxy (BW-17). The complete fix is to hash-pin the sidecar's whole Python closure
# (`uv export` -> `pip install --require-hashes`); see sidecar/resolver/constraints.txt.
COPY sidecar/resolver/constraints.txt /app/constraints.txt

# dnslib pinned to an exact version: it is the UDP server and the query-record producer, so a
# floating version could change packet handling under us. Pure-Python, no compiled deps. Bump
# deliberately.
RUN pip install --no-cache-dir --constraint /app/constraints.txt dnslib==0.9.25

# Install Bellwether so the entry can import the resolver core (decide_query, the query serializer,
# load_resolver_from_env). Only the package metadata and source are copied — never the venv, tests,
# or git tree — so the build context stays small and reproducible.
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir --constraint /app/constraints.txt /app

# The resolver entry, at the fixed path the launcher references
# (capture.dns_sidecar.RESOLVER_ENTRY_PATH).
COPY sidecar/resolver/resolver_entry.py /opt/bw/resolver_entry.py
