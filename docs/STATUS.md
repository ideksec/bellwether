# Status — where the build is, and what to pick up next

The entry point for a new session. Read this, then `docs/BUILDPLAN.md` for the next work
package, then `docs/spec.md` for the detail of whatever you are building.

Last updated at the end of the WP-5 work. **Update it at the end of a session, not the
start** — a status file that lags is worse than none, because it is trusted.

---

## Where the build is

| Work package | State |
|---|---|
| WP-1 — scaffolding, config, ground rules | **done** |
| WP-2 — skill parsing, three digests | **done** |
| WP-3 — ARF schema, writer, reader | **done** |
| WP-4 — sandbox lifecycle, host and container halves | **done** |
| WP-5 — capture: Plane A and Plane B | **done** |
| WP-6 — `api-loop` harness adapter | **next** |
| WP-7 — canonicalization and epoch anchoring | not started |
| WP-8 — platform baseline | not started (parallelisable, fully offline) |
| WP-9 — assertions, outcome composition, golden traces | not started |
| WP-10 — metrics | not started |
| WP-11 — verdict engine and precondition check | not started |
| WP-12 — reporting | not started |
| WP-13 – WP-20 — Phase B | not started, gated on the first-light checkpoint |

283 tests: 255 offline, 28 requiring a Docker daemon. All green.

`bellwether run` is not usable. It exits 3 and names the work package that brings it,
rather than printing an empty result that would read as a clean run.

### What WP-5 built

- **Plane A**: `bellwether.capture.HostEventSink` — a host-owned FIFO, write-only from
  the container's side (the host opens its descriptor, then chmods the node to `0222`,
  so the read end cannot be opened to steal events), bind-mounted as a single file so
  in-container `unlink` fails with `EBUSY`. Deadline-driven at every point; malformed
  lines are recorded, not dropped; byte caps degrade the plane to `partial` with the
  reason stated rather than silently.
- **Plane B**: all three §10.2 zones now have host-side overlay upper directories —
  harness state and scratch were tmpfs, which dies with the container and made their
  writes unobservable. `DockerBackend.zone_changes` reads each zone's diff;
  `bellwether.capture.collect_filesystem_events` partitions with zone membership and
  canary-path flags on every event.
- **Trace side**: `bellwether.trace.filesystem_actions` turns capture events into ARF
  action records (capture cannot import trace — the layering runs `capture -> trace`),
  and `assemble_coverage` produces the §10.7 block with every plane stated, the unbuilt
  ones as `unavailable` naming the work package that brings them.
- The §24 capture-plane integration tests: `tests/test_capture_docker.py` runs known
  workloads and asserts each plane records exactly the expected events; the offline half
  is `tests/test_capture_planes.py`.
- The ARF null-emission question is settled: `None` fields are omitted at serialisation
  (lossless — absence and `null` read identically). See spec-notes.

## What to do next

**WP-6 — the `api-loop` harness adapter.** A provider-thin agent loop that runs inside
the sandbox, drives a model through tool calls, and writes hook events to the Plane A
sink (the sink's wire format is JSONL objects; the adapter defines the event schema —
that translation into Plane A `Action` records deliberately did not land in WP-5).
`bellwether.harness` is empty; §9.4 defines the adapter contract, and golden traces for
the offline analysis path are one of its outputs.

**WP-8 (platform baseline) is a reasonable alternative** if you want something entirely
offline. The build plan lists it as parallelisable with WP-5–7, and its done-criterion —
`~/.cache/../.aws/credentials` raising a near-miss rather than being absorbed — is
directly served by the traversal handling already in `bellwether.sandbox.zones`.

## Outstanding actions

### Code

| Item | Where | Why it is still open |
|---|---|---|
| `fixture.yaml` generated content | §9.1 step 1 | A half-designed generator is worse than none. Needs a schema decision. |
| §21 enforced-settings refusal exists only in `doctor` | `cli/app.py`, `config/models/config.py` | Needs the orchestrator that does not exist yet. Wire it when `run` lands. |
| Sink container path is chosen ad hoc by the caller | `sandbox/docker.py` `sink_bind` | §3.5: a fixed FIFO path is an instrumentation tell. The WP-6 adapter should draw it per run, plausibly via `sandbox/identifiers.py`. |
| Plane A events are captured but not yet translated to ARF actions | `capture/sink.py` | Deliberate: the WP-6 adapter defines the event schema, so the translation lands with it. |
| §16.4 precondition check not implemented | WP-11 | Must refuse before any run executes, so it lands with the verdict engine. |
| `pids_limit` exit reason never produced | `sandbox/docker.py` | Docker gives no distinct exit code; needs another signal to distinguish it from `harness_error`. |
| Held-out probe set (§7.6, §3.5) | — | Must not appear in `--help`, the README, or the public corpus when it lands. |

### Repository settings — human-only

| Item | Status |
|---|---|
| Branch protection on `main` requiring `check` and `container` | **reported done; not verifiable from here** — the branches API still shows `main` as `protected: false`. That is consistent with a *ruleset* rather than classic branch protection, which the flag does not reflect. Worth confirming, because it is the control that closes the stale-check hazard below. |
| Private vulnerability reporting enabled | open — `SECURITY.md` already points people at it |
| Dependabot | open |
| CodeQL | open — thin to be missing on a repo about supply chain |

There is also a stray branch, `claude/bellwether-code-review-t8xuzw`, left by the review
session. Nothing depends on it; delete it when convenient.

## Things a new session must know

### The Docker daemon does not start itself

`.claude/hooks/session-start.sh` starts it and installs dependencies. It is registered in
`.claude/settings.json` and runs synchronously, so the session waits for it. If the
container tests skip, check `/var/log/dockerd.log`.

### Not every container registry is reachable

The environment's network policy allows registry APIs but denies the CDNs that Docker Hub,
GHCR and public ECR redirect blobs to — so a pull fails part-way through with a 403.
`mcr.microsoft.com` works because it serves its own blobs, and is the default for
`BELLWETHER_TEST_IMAGE`. CI uses `alpine:3.20`, which is fine there because GitHub runners
have open egress.

### Commits pushed from an agent session do not trigger CI

This is the one that has already caused a real problem. GitHub does not create workflow
runs for pushes authenticated with the session token; opening a PR through the API *does*.
The consequence:

> A pull request can display green checks that ran against an **older commit** than the
> one that would merge.

That happened on #5, which showed two green checks against `efee94a` while its head was
`435a8f5` — the commit carrying three security fixes. Branch protection now blocks it,
because GitHub evaluates required checks against the head SHA. **Do not turn that
protection off**, and if you are ever reasoning about a green check, confirm its SHA
matches the PR head.

### The container tests need root

Mounting the host-side overlay upper directory is the privilege the host has and the
container does not — the whole capture architecture in one line (§10.0).

```bash
sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker
```

They skip with a stated reason where the daemon or the privilege is missing.

## How the work has been going wrong

Worth reading before adding code, because the pattern has held across every defect found
so far — eleven of them, across two self-reviews and one independent review.

**Every single one was something that looked like it worked.** Not one was a logic error
of the ordinary kind. A representative sample:

- `SeededRng` re-seeded on every call, so five canaries would have been five *identical*
  markers. Its test compared different seeds and passed.
- The skill digest was delimited by newlines, which are legal in filenames — so
  `package_digest` was forgeable, and it binds a human review attestation.
- A named pipe in the workspace hung the host-side collector forever, after the container
  had already exited, with no timeout. `mkfifo` needs no capability.
- `/home/agent/.claude` was declared writable in the isolation profile and consumed by
  nothing, so it was read-only. Every harness state write would have failed with `EROFS`.
- The CI guard that exists to stop the container tests passing by being absent read a
  blank line and would have errored on every run.

Two working rules follow:

1. **A passing test is not evidence.** Several of these had tests that passed while the
   code was wrong, because the test asserted the wrong thing.
2. **Run it.** Every defect above was found by executing something — a container, a
   reproduction script, a CI step by hand — and not by reading code. The three found by
   the independent review were all reproduced directly before being reported.

## Reference

- `docs/spec.md` — the specification, revision 3. Authoritative for *what*.
- `docs/BUILDPLAN.md` — authoritative for *order*, and for what "done" means per package.
- `docs/spec-notes.md` — every deliberate divergence from the spec, with reasoning.
  Eighteen entries. Read it before changing anything in the skill, sandbox, capture or
  config layers.
- `CONTRIBUTING.md` — the five mechanically-enforced rules and how to run everything.
