#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# Two jobs: install the dev dependencies, and start a Docker daemon so the WP-4
# container integration tests can run. Neither survives a container restart, and
# without the daemon those tests skip silently — which for a tool whose subject is
# "degraded coverage must be visible" is the wrong kind of quiet.
#
# Idempotent and non-interactive; safe to run repeatedly.
set -euo pipefail

# Local machines manage their own toolchain and daemon.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
if command -v uv >/dev/null 2>&1; then
  uv sync --group dev
else
  echo "session-start: uv not found; skipping dependency install" >&2
fi

# ---------------------------------------------------------------------------
# Docker daemon
#
# Needed by the tests marked `docker`. --iptables=false because the sandbox has no
# netfilter modules to program and the daemon refuses to start without the flag;
# the container integration tests run with --network none, so no bridge is required.
# The proxy-sidecar work of WP-13 will need networking and will revisit this.
# ---------------------------------------------------------------------------
if ! command -v dockerd >/dev/null 2>&1; then
  echo "session-start: dockerd not installed; container tests will skip" >&2
  exit 0
fi

if docker info >/dev/null 2>&1; then
  echo "session-start: docker daemon already running"
  exit 0
fi

mkdir -p /var/log
nohup dockerd --iptables=false --ip6tables=false >/var/log/dockerd.log 2>&1 &
disown || true

for _ in $(seq 1 30); do
  if docker info >/dev/null 2>&1; then
    echo "session-start: docker daemon started"
    exit 0
  fi
  sleep 1
done

# Not fatal: the container tests skip when no daemon is present, and the rest of the
# suite is offline by design. Say so rather than failing the session.
echo "session-start: docker daemon did not come up in 30s; see /var/log/dockerd.log" >&2
echo "session-start: container-marked tests will skip" >&2
