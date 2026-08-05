# Status — where the build is, and what to pick up next

The entry point for a new session. Read this, then `docs/BUILDPLAN.md` for the next work
package, then `docs/spec.md` for the detail of whatever you are building.

Last updated at the end of the WP-9 work. **Update it at the end of a session, not the
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
| WP-6 — `api-loop` harness adapter | **done** |
| WP-7 — canonicalization and epoch anchoring | **done** |
| WP-8 — platform baseline | **done** |
| WP-9 — assertions, outcome composition, golden traces | **done** |
| WP-10 — metrics | **next** |
| WP-11 — verdict engine and precondition check | not started |
| WP-12 — reporting | not started |
| WP-13 – WP-20 — Phase B | not started, gated on the first-light checkpoint |

393 tests: 358 offline, 35 under the `docker` mark. All green.

`bellwether run` is not usable. It exits 3 and names the work package that brings it,
rather than printing an empty result that would read as a clean run.

### What WP-9 built

- **The deterministic catalogue** (`assertions/engine.py`) over an `EvidenceIndex`
  extracted once per trace: activation, tool calls (bounds, `args_match`, sequences),
  overlay-backed write assertions, output/duration/token/exit checks, workspace-backed
  `content_match` and `artifact_valid`. Presence and absence claims are asymmetric —
  presence can pass on Plane A evidence; absence needs the plane that could have seen
  the thing, so the egress/DNS/credential/process assertions return `not_evaluable`
  carrying the §10.7 reason until WP-13/15/16/18 land (spec-notes).
- **Outcome composition** (`assertions/results.py`): §12.7's table exactly, including
  the deliberate exit-reason split (timeout/oom/pids_limit fail; budget_exceeded/
  cancelled are not_evaluable) and `excluded_quality` for egress-induced failures.
- **Auto-derivation and Declared vs Observed** (`assertions/derive.py`): the
  non-circular §12.5 derivation (deny lists and write/egress globs become catalogue
  specs; allowlists are evaluated against the observation), and the scope table with
  `supported` / `exceeded` / `unused` / `not_evaluable` at tier 3, post-baseline.
  `unused` is an absence claim and gates on the plane accordingly.
- The committed golden trace evaluates end-to-end offline — the WP-9 done-when — with
  the honest outcome `not_evaluable` when a required claim has no plane.

## What to do next

**WP-10 — metrics (§13).** The nondeterminism math: Wilson intervals with the Pocock
boundary (`POCOCK_BOUNDARY_Z` is already in constants), plain and weighted capability
Jaccard, trajectory clustering over WP-7's step sequences, directory instability, the
sensitive-directory flag consuming `CanonicalTrace.sensitive_hits`, the BCI with
renormalisation, and §11.4's specified edge cases (empty-set Jaccard = 1.0, entropy at
N = 1 is `not_evaluable`, `0·log₂0 = 0`). §24 requires property-based tests for
bounds, identity, monotonicity and renormalisation — budget for them.

## Outstanding actions

### Code

| Item | Where | Why it is still open |
|---|---|---|
| `fixture.yaml` generated content | §9.1 step 1 | A half-designed generator is worse than none. Needs a schema decision. |
| §21 enforced-settings refusal exists only in `doctor` | `cli/app.py`, `config/models/config.py` | Needs the orchestrator that does not exist yet. Wire it when `run` lands. |
| Sink container path is chosen ad hoc by the caller | `sandbox/docker.py` `sink_bind` | §3.5: a fixed FIFO path is an instrumentation tell. The WP-17 adapter (the sink's writer) should draw it per run, plausibly via `sandbox/identifiers.py`. |
| The FIFO event sink has no writer yet | `capture/sink.py` | `api-loop` reports its own events in-process; the sink's writer is the `claude-code` adapter's hook stream (WP-17). The sink is built and container-tested. |
| Live model client | `harness/provider.py` | Deferred to WP-13 on purpose: no observed egress path exists yet for it (spec-notes §9.4). |
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

### Check a green check's SHA against the PR head

Pushes authenticated with the session token do not create `push`-event workflow runs.
Opening a PR does create a run — and, observed on #8, so does pushing to a branch with
an **open** PR (the `pull_request` synchronize event fires). The gap is therefore
branches with no open PR, and any state where a run failed to materialise. The
consequence when it bites:

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
  Twenty-five entries. Read it before changing anything in the skill, sandbox, capture or
  config layers.
- `CONTRIBUTING.md` — the five mechanically-enforced rules and how to run everything.
