# The sandbox image for the `claude-code` harness (§9.4 adapter 1, §9.2). The Claude Code CLI
# runs *inside* this container as the agent under observation; nothing that produces evidence
# does (§10.0). Its model calls leave only through the recording proxy, carrying the sandbox-scoped
# token the proxy swaps for the real key (§3.3 invariant 1), so this image holds no credential.
#
# Base pinned by digest, not tag (tools/pin_lint.py enforces this): a supply-chain tool that pulled
# a mutable base for its own sandbox would undermine its thesis. To update, run
# `docker buildx imagetools inspect node:22-bookworm-slim` and replace the digest here.
FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5

# What a headless agent session needs beside Node: git (the CLI inspects the workspace's repo
# state), ripgrep (Grep/Glob back onto it; the CLI bundles one but the system build is the
# documented Linux dependency), ca-certificates (the proxy CA is *added* to a store that must
# exist — §9.2's TLS interception table), and a POSIX shell for the hook commands.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ripgrep ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

# The CLI, pinned to the exact version whose stream and hook formats the adapter was built
# against (tests/golden/claude-code — `claude_code_version: 2.1.257`). Bump deliberately, and
# re-take the golden session when you do: a format change must break a test, not empty Plane A.
RUN npm install -g @anthropic-ai/claude-code@2.1.257 \
    && npm cache clean --force

# The sandbox runs as uid 1000 (§9.2 — the isolation profile passes `--user 1000:1000`), and the
# node image already owns that uid as `node`. The agent's home is /home/agent (the harness-state
# zone /home/agent/.claude is mounted over it at run time); the directory must exist and be owned
# by the uid so a read-only root still lets the CLI find its state directory.
RUN mkdir -p /home/agent /work \
    && chown 1000:1000 /home/agent /work

ENV HOME=/home/agent
WORKDIR /work
