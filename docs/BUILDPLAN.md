# Bellwether — v0.1 Build Plan

Companion to [`spec.md`](spec.md) (revision 3, merged). The spec is the source of truth for
*what*; this document is the source of truth for *order*, and for what "done" means at each step.

Hand this file and the spec to Claude Code together. Work packages are numbered in dependency
order. **Do not start a package whose predecessors are not green.**

---

## 0. Ground rules for the whole build

These apply to every package and should be set up before WP-1.

- **Python 3.12+, `uv`, `pyproject.toml`.** Single repo, package root `src/bellwether/`.
- **Module boundaries from §8.1 are enforced mechanically** — add the `import-linter` contract in
  WP-1, not later. The graph is acyclic and flows
  `config → skill → scan → sandbox → harness → capture → trace → assertions → metrics → verdict → report → cli`.
  `metrics` must never import `verdict`.
- **`mypy --strict`** on `metrics`, `trace`, `verdict`, `capture` from the first commit in each.
- **Determinism rules (§24) are implemented as they are needed, not retrofitted.** Sorted sets,
  `round(x, 6)` at serialisation only, no reliance on `hash()` ordering, sorted file walks, seeded
  and recorded RNG. Retrofitting determinism into a codebase that assumed it is a rewrite.
- **Never hard-code a model ID.** Aliases (`frontier`, `mid`, `small`) resolve through config. A
  literal model string anywhere outside a user's own `config.yaml` is a bug.
- **Language discipline lint (§16.3)** — the rule banning "safe"/"secure"/"verified"/"certified"
  from user-facing strings goes in with the first user-facing string, in WP-1.
- Every package ends with tests that run **offline**, with no API key, except where explicitly
  noted.

---

## Phase A — Skeleton that walks (no network layer)

This phase ends at the **first-light checkpoint** in §25: `benign-stable` end to end, proxy and
resolver bypassed, egress assertions disabled. Do not build the network layer in parallel with
this; the debugging surfaces are hard to separate.

### WP-1 — Project scaffolding and config
**Spec:** §8.1, §21, §22
Skeleton package layout, `pyproject.toml`, `uv` lock, `ruff`/`mypy`/`import-linter`/language-lint
in CI. `bellwether.config` with pydantic models for `config.yaml`, `policy.yaml`,
`evals/manifest.yaml`, `evals/scenarios.yaml`. Validation errors render as human sentences naming
file, path within it, and allowed values — never stack traces.
**Done when:** `bellwether --help` runs; every example YAML in the spec parses; every deliberately
malformed variant produces a readable error; the import-linter contract passes.

### WP-2 — Skill package parsing
**Spec:** §6.1, §6.2, §6.3
Frontmatter parsing with unknown-field preservation. **Three digests** — `package_digest`,
`payload_digest`, `description_digest` — over a **sorted** file walk. Executable inventory with
interpreter detection. Token estimates. Manifest loading including the digest-bound review block.
**Done when:** digests are byte-reproducible across two machines and two filesystem orderings;
`payload_digest` is unchanged by edits under `evals/`; `description_digest` changes on a
description-only edit and not otherwise.

### WP-3 — ARF schema and writer
**Spec:** §11.1–11.4
Pydantic models for `run_header`, `action`, `run_footer`. JSONL writer. The `canon` block with
`canon_version`, `traj_planes`, `trajectory_cluster_threshold`, `weights_digest`. Incomplete-trace
detection (no footer ⇒ `not_evaluable`).
**Done when:** round-trip write→read is lossless; a truncated file is detected as incomplete; the
schema validates the golden traces committed in WP-9.

### WP-4 — Sandbox lifecycle (no network)
**Spec:** §9.1 steps 1–11, §9.2, §3.5, §10.2
Docker session management. Fixture materialisation with **normalized mtimes, modes, ownership**.
Randomised workspace root, hostname, container name; pinned `/etc/machine-id`, timezone, locale.
Overlay mount with host-side upper dir. **Three zones** (§10.2) configured and recorded. Payload
install by **allowlist** — `evals/` must never enter the container. Isolation profile:
`--cap-drop=ALL`, `--read-only`, `--pids-limit 512`, `--security-opt=no-new-privileges`,
900s default timeout.
**Done when:** a container runs with `--cap-drop=ALL` and no capture code inside it; the overlay
upper dir is readable from the host and yields the changed-path set; two materialisations of the
same fixture are byte- and metadata-identical; an integration test asserts no file under `evals/`
exists inside the container.

### WP-5 — Capture: Plane A and Plane B
**Spec:** §10.0, §10.1, §10.2
Host-owned event sink (FIFO or unix socket — a writable file in a mount is not acceptable).
Overlay-diff filesystem capture, partitioned by zone, content-only hashing with metadata recorded
separately. Zone membership on every filesystem action record.
**Done when:** the capture-plane integration tests of §24 pass — small non-agentic container
workloads with known behaviour, asserting each plane records exactly the expected events. These
tests are the ones that would have caught the revision-1 capability contradiction; they matter more
than they look.

### WP-6 — `api-loop` harness adapter
**Spec:** §9.4, §9.5
Minimal agent loop against a provider messages/tool-use API with Bellwether-implemented tools
(read, write, bash, fetch). Provider abstraction with alias resolution. `HarnessCapabilities`
including `egress_observable` and `infrastructure_endpoints`.
**Note:** every trigger-derived metric from this adapter carries `harness-specific: not portable`.
Wire that label in now, not later.
**Done when:** a run produces a complete ARF trace with Plane A and Plane B populated; tool calls
carry their originating id for the explicit-correlation path in WP-10.

### WP-7 — Canonicalization and epoch anchoring
**Spec:** §11.4, §11.5, §11.6
Path normalisation, step signatures at tier 1, three capability tiers, platform-baseline
subtraction. **Epoch anchoring** — the spine, epoch assignment, explicit correlation via
`anchor_seq`, within-epoch content ordering by `(plane_priority, kind, normalized_target,
stable_hash)`. Never sort across planes by time.
**Done when:** the same event set produces byte-identical ordering across 100 runs and across
machines; a synthetic test that jitters non-spine timestamps by ±2s produces an unchanged sequence.
**This is the package most likely to be got subtly wrong. Over-test it.**

### WP-8 — Platform baseline
**Spec:** §12.6
`platform-baseline.yaml` loader, versioned, keyed to sandbox image. Path/process/tool matching
against `observed − baseline`. Process tree attribution (`helpers_of`). Near-miss flagging at
`medium`. Traversal sequences never resolve *into* a baseline match.
**Done when:** a run of `benign-stable` produces zero spurious `exceeded` entries; a
`~/.cache/../.aws/credentials` read raises a near-miss finding rather than being absorbed.

### WP-9 — Assertions and outcome composition
**Spec:** §12.1, §12.2, §12.5, §12.7
The deterministic catalogue. Auto-derived assertions from `declared_scope` (note the corrected,
non-circular `tools.allow` derivation). Run outcome function — including the deliberate split where
`timeout`/`oom`/`pids_limit` are failures but `budget_exceeded`/`cancelled` are `not_evaluable`.
Every assertion returns `pass`/`fail`/`not_evaluable` with a reason and evidence `seq` list.
**Also:** commit the **golden traces** here. Everything downstream must be testable with no API key.
**Done when:** the metrics → verdict → report path runs entirely offline from golden traces.

### WP-10 — Metrics
**Spec:** §13 in full, especially §13.1, §13.5.1, §13.5.1.1
Wilson interval parameterised by z. Pocock boundary as a **constant** (z = 2.289) with the
achievable-lower-bound table as a unit test. Sequential scheduler with looks at 6/12/20, the
capability-agreement continuation rule, and `held_open_for_capability` recording. Trigger entropy.
Trajectory clustering with the lexicographic tie-break. Plain **and risk-weighted** tier-1 Jaccard.
Directory instability, sensitive-directory flag, rare-capability report at < 100%,
`max_rare_capability_risk` gate. BCI with mandatory renormalisation.
**Property-based tests are mandatory here, not optional:** bounds, identity, monotonicity, every
edge case in §11.4, renormalisation, rounding-independence of `outcome_consistency`, and
`J_weighted == J_plain` when all weights are equal.
**Done when:** the §13.1 lower-bound table reproduces exactly; the §13.5.1.1 sensitivity table
reproduces exactly; and `rare-canary-reader` blocks identically at N = 6, 12, 20.

### WP-11 — Verdict engine and precondition check
**Spec:** §16.1–16.4
Gate evaluation, **per target taking the worst result**. `not_evaluable` ⇒ block on a required
gate, with the coverage reason string attached. `descriptive_only` can never be `ready`. **§16.4
precondition check runs before any run executes** and names gate, target, and remedy.
**Done when:** the three unsatisfiable combinations in §16.4 are each caught before a single API
call is made, with the specified message shape.

### WP-12 — Reporting (markdown + `summary.json`)
**Spec:** §17.1, §17.2, §13.8
Artifact tree, schema-versioned `summary.json`, markdown report. BCI never rendered without pass
rate adjacent; "consistently failing" annotation wherever p̂ < 0.5. Every figure carries
`n_evaluable` and the look.
**Done when:** `summary.json` validates against its schema; a golden-trace run produces
byte-identical output across two invocations.

### ▶ FIRST-LIGHT CHECKPOINT
`benign-stable` runs end to end, proxy and resolver bypassed, egress assertions disabled and
reported as `not_evaluable` with a reason. **Gate the rest of v0.1 on this.** If the skeleton does
not walk, adding a network layer will not help you find out why.

---

## Phase B — The trust boundary

Nothing here is optional for v0.1. §3.3's critical invariants are established in this phase, and a
v0.1 without them ships a security tool whose own key handling is broken.

> **Progress note (read this): v0.1 is functionally complete.** Phase A is done, and all of Phase B
> has since landed in a **dependency order that differed from the raw numbering** — WP-13 (recording
> proxy) wired into the executor, then WP-15 (DNS) → WP-16 (canaries) → WP-19 (noise floor) → WP-18
> (coverage matrix) → WP-17 (`claude-code` adapter) → WP-20 (corpus). Getting there inserted work
> these WP numbers don't name — the dual-homed proxy in the executor, the `bellwether run` provider
> plumbing, the CI live-proof, and evidence upload — legitimate connective tissue that made WP-13
> usable end to end. **Both harnesses are now proven live**: a benign skill reached `ready` on a
> labelled PR under `api-loop` and, on PR #65, under the real Claude Code CLI (WP-17) — 8 gates pass,
> functional 6/6. **Every v0.1 work package is built.** What remains are post-v0.1 loose ends, none
> blocking the v0.1 line — see the "Post-v0.1 loose ends" block below, and `docs/STATUS.md` →
> "What's next" for the live, ordered version. The WP definitions below remain the authoritative
> *specs*.
>
> **Post-v0.1 loose ends (non-blocking).** Self-contained, do first: (1) **promote the live
> egress/DNS gates from `warn` to `block`** now that both harnesses run clean (config + a rot test);
> (2) **WP-14 live doctor interception probe** — `doctor` issues a real request from inside the
> container and asserts the proxy recorded it, and that a direct public-resolver query fails (the
> live half of the WP-14/WP-15 done-whens; host core done); (3) **per-run sink path** from the
> identifier stream, replacing the fixed `/dev/bellwether-events` (§3.5); (4) **`openai_compatible`
> provider** — the Chat-Completions message-shape translation behind the `ModelClient` seam. Then the
> remaining §24 corpus rows, each gated on a post-v0.1 subsystem: **static scanner** (`git-peeker`,
> `obfuscated-injection`, `fetch-and-exec`, `eval-aware`); **probe suite** (`over-triggering`,
> `prompt-channel-thief`, `server-tool-user`, `model-divergent`, `oom-hog`); **real-network corpus
> run** (the chunked/interleaved thieves, `telemetry-noisy`).

### WP-13 — Recording proxy sidecar
**Spec:** §10.5, §10.5.0, §10.5.1, §3.3, §22
mitmproxy in a **sidecar container**, pinned by digest, behind a `RecordingProxy` interface.
Default-deny allowlist. Sandbox-scoped token with proxy-side real-credential injection — the real
key must never be readable inside the container and must never enter an artifact. Per-run request
and token caps. **Egress classification** into `model_api` / `harness_infrastructure` /
`skill_attributed`. `possible_egress_induced_failure` correlation. Clock domain shared with the
sandbox.
**Done when:** an integration test asserts the real key is absent from the container's environment,
filesystem, and every artifact; `no_egress` passes for a skill on a telemetry-emitting harness.

### WP-14 — CA trust chain
**Spec:** §9.2
Install the proxy CA into **every** mechanism in the §9.2 table — system store,
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`.
**Done when:** `bellwether doctor` verifies interception **by issuing a real request from inside
the container and asserting the proxy recorded it**, and fails loudly if it did not. A silent
interception failure produces zero-egress traces that read as a clean skill; this check is the only
thing standing between that failure and a false "clean" verdict.

### WP-15 — Controlled DNS resolver
**Spec:** §10.6, §3.3 invariant 3, §9.2
Resolver sidecar: allowlist-only resolution, NXDOMAIN plus full logging for everything else.
`dns_query` / `dns_blocked` action records. Bridge configured so UDP/53 has no route except the
resolver.
**Done when:** `bellwether doctor` attempts a direct query to a public resolver from inside the
container and asserts it **fails**; `dns-thief` is detected.

### WP-16 — Canaries
**Spec:** §10.4 in full
Planting from a per-evaluation `canary_seed`, randomised markers with no fixed prefix, randomised
paths drawn from a pool. **Destination classification** (§10.4.1). **Decode-then-match** with
base64/base64url/base32/hex/URL/HTML-entity/reversal and one round of nesting; windowed matching at
≥12 chars; DNS label-separator stripping (§10.4.2). **Redaction at capture time** with evidentiary
fingerprints (§10.4.3). Canary content excluded from `fixture_digest`.
**Done when:** `canary-thief` and `dns-thief` block with evidence linked to specific trace records;
`legit-credential-reader` passes **without** a leak finding; `encoded-chunked-thief` is committed as
a documented xfail; no artifact anywhere contains a raw canary value.

### WP-17 — `claude-code` adapter
**Spec:** §9.4, §10.1
CLI subprocess with structured streaming output, plus the hook mechanism writing to the **host-owned
sink**. Cross-check the two sources; disagreement is a `trace_inconsistency` finding per the §10.8
matrix. Declare `infrastructure_endpoints` and set any telemetry-disable flag, recording that it was
set. **Consult the harness's current CLI and hooks documentation at build time — flag names change.**
**Done when:** trigger metrics are produced from a real harness rather than from Bellwether's own
prompt assembly; `telemetry-noisy` produces no false egress finding.

### WP-18 — Plane precedence and coverage
**Spec:** §10.7, §10.8
The precedence matrix. `trace_inconsistency` raised only where both planes are in-domain and at a
fidelity where absence is meaningful. Coverage block with per-plane fidelity **and reason strings**.
**Done when:** a full `benign-stable` run at overlay-diff fidelity produces **zero**
`trace_inconsistency` findings.

### WP-19 — Noise-floor calibration
**Spec:** §24
Run `benign-stable` with `--deterministic-sampling`. Assert trajectory dispersion over **Plane A
alone is exactly 0**. Record the cross-plane residual as `noise_floor` in `summary.json`. Repeat
under concurrent load and assert the floor does not move materially. Implement `at_noise_floor`
reporting.
**Done when:** all three assertions hold. **A nonzero Plane-A-only floor means WP-7 is wrong** —
go back and fix epoch anchoring rather than accepting the number.

### WP-20 — Corpus and acceptance
**Spec:** §24, §25
The eleven v0.1 corpus skills with expected-verdict fixtures, payloads base64-encoded and
materialised by a build step. CI asserts each expected verdict.
**Done when:** the full §25 v0.1 acceptance list passes.

---

## Sequencing notes

- **WP-7 (epoch anchoring) and WP-19 (noise floor) are a pair.** WP-19 is the only test that proves
  WP-7 works. Do not defer it to "polish"; a wrong WP-7 silently corrupts the project's
  differentiating metric and everything built on top of it will look plausible.
- **WP-13 through WP-16 are one coherent chunk** and are hard to test separately. Build the proxy
  first with a trivial allowlist, then CA, then DNS, then canaries — but expect to iterate across
  all four.
- **WP-10's property tests are the specification.** If a property test and the prose disagree,
  the prose is probably right and the test encodes a misreading — but check both, and record the
  resolution in the spec.
- **Parallelisable:** WP-2/WP-3 after WP-1; WP-8 alongside WP-5–7; WP-12 alongside WP-11.
- **Not parallelisable:** anything in Phase B before the first-light checkpoint.

## Things to verify against reality before relying on them

The spec is internally consistent but several of its numbers are provisional and were flagged as
such in §27. Treat these as inputs to calibrate, not constants:

- `trajectory_cluster_threshold: 0.2` — calibrate against `benign-stable` / `benign-chaotic` once
  they exist; a threshold below the measured noise floor is meaningless.
- Look points 6/12/20 and thresholds 0.5/0.6/0.7 — re-derive after v0.2 from observed stopping
  distributions.
- The §19.1 cost table — regenerate from real corpus runs before publishing anything based on it.
- Harness CLI flags and hook APIs — read the current docs; do not trust the spec's descriptions of
  another project's interface.
