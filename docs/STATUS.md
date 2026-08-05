# Status — where the build is, and what to pick up next

The entry point for a new session. Read this, then `docs/BUILDPLAN.md` for the next work
package, then `docs/spec.md` for the detail of whatever you are building.

Last updated at the end of the WP-12 work. **Update it at the end of a session, not the
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
| WP-10 — metrics | **done** |
| WP-11 — verdict engine and precondition check | **done** |
| WP-12 — reporting (`summary.json` + Markdown) | **done** |
| Analysis orchestrator (trace → verdict → artifact tree) | **done** |
| Sandbox execution driver (`RunExecutor`) | **done** |
| ▶ First-light checkpoint — `benign-stable` end to end in a real sandbox | **reached** |
| WP-13 – WP-20 — Phase B | not started; the checkpoint that gated them is now met |

485 tests: 449 offline, 36 under the `docker` mark. All green.

`bellwether run` is not usable. It exits 3 and names the work package that brings it,
rather than printing an empty result that would read as a clean run.

### What WP-12 built

The report layer, in `bellwether.report` (renders; never computes — everything here was
decided upstream in `metrics` and `verdict`):

- **`summary.py`**: the schema-versioned `summary.json` (§17.2) as `extra='forbid'`
  pydantic models, `render_summary_json` routing through `determinism.canonical_json`
  (sorted keys, floats rounded once), and `summary_json_schema()` — the JSON Schema is
  *generated* from the models and shipped at `report/schemas/summary.schema.json`, with a
  drift test asserting it matches. The done-when (byte-identical across two invocations)
  falls out of the determinism layer.
- **`figures.py`**: the three §13.8 figures as deterministic monospace text — the
  per-scenario strip chart (five distinct glyphs; a timeout is not drawn like an
  assertion failure; look boundaries marked; `n` and the look on every row), the
  trajectory cluster list (largest first), and the **capability heatmap** (tier-3 grouped
  under tier-1, high-risk flagged — the flagship). Row order is sorted, so shuffling the
  input never changes the bytes.
- **`markdown.py`**: the PR comment (§18.2), hand-rolled so the presentation rules with
  teeth are unit-tested Python, not template branches — the BCI never rendered without
  the pass rate beside it, the "consistently failing" annotation wherever `p̂ < 0.5`, and
  the §2 limitations footer rendered whole from `constants.REPORT_LIMITATIONS`.

WP-12 is `summary.json` + Markdown; the eleven-view HTML site (§17.4), the two findings
containers (§17.3), and the artifact tree (§17.1) are a later package (see spec-notes
§17.4). 16 report tests.

### What the analysis orchestrator built

The analysis half of `bellwether run`, in `bellwether.cli.orchestrator` and
`bellwether.cli.artifacts` — the thing that *assembles* every stage below it into a
verdict, but does not execute runs itself:

- **`analyse_run`**: one trace → its per-run reading (the §12.7 run outcome from the
  assertion results, the §11.4 canonical capability sets, the trajectory step sequence).
- **`aggregate`**: a repetition set → one `SetReading` through the §13 metrics — sequential
  pass-rate design (§13.1), risk-weighted capability Jaccard (§13.5), trajectory clustering
  (§13.4), the BCI (§13.7).
- **`orchestrate`**: populates the §16.2 gates from the readings (worst target per gate),
  composes the verdict, assembles the `Summary`, and writes the §17.1 artifact tree
  (`summary.json`, `verdict.json`, `report/pr_comment.md`, per-run `traces/` and
  `canonical/`).
- **`RunExecutor`** is the seam for the execution half.

### What the execution driver built (first-light reached)

`SandboxRunExecutor` in `bellwether.cli.execution` — the WP-6 container wiring lifted behind
the `RunExecutor` seam. Given a `RunPlan` it prepares a fresh sandbox, runs one repetition
through the `api-loop` adapter, captures both planes on the host, assembles the ARF trace,
and returns an `ExecutedRun`. One repetition, one fresh sandbox (a repetition set is a
distribution over *independent* runs — sharing state would fabricate consistency). The model
side is injected as a `ModelClient` per target, so the `harness → sandbox` boundary and the
no-hard-coded-model rule both hold; at first-light the client is scripted (the live client
lands in WP-13).

**The first-light checkpoint is reached** (`test_execution_docker.py`): `benign-stable` runs
end to end in a *real* container six times — overlay mount, container exec, two-plane
capture, proxy and resolver bypassed — the orchestrator turns those six real traces into a
**`conditional`** verdict (every evaluable gate passes; egress `not_evaluable` with a reason
until the proxy lands), and the artifact tree lands on disk. The skeleton walks. The
`conditional`-not-`ready` result is the tool refusing to call an unobserved channel clean,
holding even for its own first run.

## What to do next

**Phase B — the trust boundary (WP-13 onward).** The first-light checkpoint that gated the
rest of v0.1 is met, so the network layer can now land on a skeleton known to walk. WP-13 is
the **recording proxy sidecar** (§10.5): default-deny egress allowlist, sandbox-scoped token
with proxy-side real-credential injection, egress classification. It also brings the **live
model client** (`harness/provider.py`), which is what lets `bellwether run` execute a real
skill against a real model from the CLI — today the executor needs an injected client, so
`run` still names WP-13. With egress observable, `benign-stable` reaches `ready`. Then wire
the precondition check and weight validation into `doctor`/`run`, the §21 enforced-settings
refusal, and the FIFO sink writer — see the table below.

## Outstanding actions

### Code

| Item | Where | Why it is still open |
|---|---|---|
| `fixture.yaml` generated content | §9.1 step 1 | A half-designed generator is worse than none. Needs a schema decision. |
| §21 enforced-settings refusal exists only in `doctor` | `cli/app.py`, `config/models/config.py` | Needs `run` to be fully wired (the execution driver). Wire it then. |
| Precondition check and weight validation not yet wired to `doctor`/`run` | `verdict/precondition.py`, `verdict/validation.py` | Built and tested; §16.4 says surface in `doctor` too. Wire when the execution driver lands. |
| Sink container path is chosen ad hoc by the caller | `sandbox/docker.py` `sink_bind` | §3.5: a fixed FIFO path is an instrumentation tell. The WP-17 adapter (the sink's writer) should draw it per run, plausibly via `sandbox/identifiers.py`. |
| The FIFO event sink has no writer yet | `capture/sink.py` | `api-loop` reports its own events in-process; the sink's writer is the `claude-code` adapter's hook stream (WP-17). The sink is built and container-tested. |
| Live model client | `harness/provider.py` | Deferred to WP-13 on purpose: no observed egress path exists yet for it (spec-notes §9.4). |
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
  Thirty-two entries. Read it before changing anything in the skill, sandbox, capture or
  config layers.
- `CONTRIBUTING.md` — the five mechanically-enforced rules and how to run everything.
