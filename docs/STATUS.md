# Status — where the build is, and what to pick up next

The entry point for a new session. Read this, then `docs/BUILDPLAN.md` for the next work
package, then `docs/spec.md` for the detail of whatever you are building.

Last updated at the end of the **claude-code-live** arc: the proxy is wired into the executor as a
dual-homed sidecar, and a benign skill has reached **`ready` on a live labelled PR with egress
observed under *both* harnesses** — api-loop and, now, the real Claude Code CLI headless in the
sandbox (PR #65, `claude-code-live-smoke`: 8 gates pass, functional 6/6, DNS clean). Every run's
evidence (per-run ARF traces + report) is uploaded from CI.
**Update it at the end of a session, not the start** — a status file that lags is worse than none,
because it is trusted.

A **security & quality review + remediation** pass then landed (`SECURITY_QUALITY_REVIEW.md`):
48 findings, of which the two Critical and seven High and most of the rest were fixed on this
branch, each with a regression test — the offline suite grew 669 → 733. Notable corrections: the
merkle digest no longer collides a symlink with a file whose content is `symlink:<target>`
(`DIGEST_FORMAT` → `/3`); `run` now refuses a §21-disabled setting above `low`; the
`max_rare_capability_risk` gate is no longer inverted; the two trajectory gates and the configured
Pocock `boundary_z` are actually enforced; `..`-traversal no longer bypasses `deny_read`/scope;
Plane B no longer pollutes the trajectory metric; base32-split-across-DNS-labels canary evasion is
closed; the config sandbox profile reaches the container; and the CI evidence upload works.

A **public-release review pass** (pre-v0.1, ahead of making the repo public) then ran the same
adversarial way — four parallel subsystem reviews plus a hands-on pass, every issue reproduced by
running code — hunting the project's signature failure mode: a control path that renders a clean
result without running the check. It found the *live* verdict under-enforcing relative to the demo
and the policy, and closed the two highest-value gaps with regression tests: **BW-47 is now fixed** —
declared **manifest scope** applies on the live `run` path (`drive_evaluation` threads
`declared_scope` as a declared-vs-observed table, decoupled from the still-stubbed network/write
derivations, the split the demo already used), so a skill that uses a manifest-denied tool no longer
reaches `ready`; and **BW-50** — the egress host/SNI canary scan now folds case, catching a
subdomain-tunnel exfil the case-sensitive scan missed. It also disclosed **BW-49**: only
`egress_outside_allowlist` drives the scored verdict, so `doctor` now names the other
`security_runtime` dispositions as captured-but-not-gated rather than letting a `block` read as an
active control. Details in `SECURITY_QUALITY_REVIEW.md` → "Public-release review pass".

The brick after the release pass closed its one disclosed-not-fixed finding: **BW-51 — the §16.4
precondition check is wired** (`cli/preflight.py`). `run` now refuses an unsatisfiable
policy/target/composition combination *before* the executor is built — a blocking egress/DNS gate
with no proxy/resolver wired, a profile requiring planes this version has not built, a target
naming a harness with no shipped adapter (which previously ran the whole sandbox under api-loop and
died on the trace-to-plan binding) — and `doctor` evaluates the same check per profile instead of
listing it as pending. Observability is composition-derived (`egress.image` → proxy, `dns.image` →
resolver), which is what keeps the preflight from refusing the proven live configuration; the
egress and DNS clauses are checked independently, since the two components are wired independently.

The brick after that opened BW-49's real fix: **canary leaks now gate the verdict** — the
`security_runtime.canaries` gate, scored from Plane C findings. A skill that exfiltrates a planted
canary to any non-model destination blocks under the shipped `canary_leak: block`; unplanted runs
defer as `not_evaluable` (an unwatched channel is never called clean); and an observed-clean set
earns its pass even at the live path's `partial` fidelity, because that fidelity's gap — the
model-API channel — feeds a *different* finding class (`canary_without_read`), which stays
deliberately unscored until its evidence can exist. The §16.4 preflight gained the matching clause
(`canary_leak: block` with canaries disabled refuses before spending), and `doctor`'s
enforced-vs-inert message now derives both lists from the one constant next to the gate assembly.
The demo/first-light paths demote `canary_leak` to warn (nothing is planted there), so their
verdicts stay honest at `conditional` on two advisory-unobserved planes.

An **Agent Plugin compatibility** brick then landed: skills packaged in an
[agent-plugins.org](https://agent-plugins.org) bundle (a `plugin.json` root with skills under
`skills/`) are first-class inputs. `bellwether run <plugin-dir>` expands to the bundled skills
(`skill/plugin.py`, lenient manifest validation on the frontmatter's reasoning);
`changed-skills` attributes a plugin-level change — the manifest, `mcp.json`, an extension
directory — to every skill the plugin carries, instead of printing "no skills changed" for a PR
that rewrote the bundle; and a bundled `mcp.json` is reported as unobserved on every expanded
skill rather than silently ignored, since this version never starts plugin MCP servers. The unit
of evaluation stays the skill; the bundle is located and described, never staged whole —
plugin-layout staging folds into WP-17 (see spec-notes §5/§6/§18).

The brick after that made **the DNS disposition a scored gate** (`security_runtime.dns`): a name
the controlled resolver refused now drives the composed verdict, with the same three-state table
as egress and canaries — unresolvered defers (`not_evaluable`), an observed refusal takes the
policy disposition, observed-clean passes (at §10.8's *absence* bar, chosen in advance since the
plane records `full`). Scoring it forced the live smoke to observe the plane: `dns.image` is now
set in `examples/live/config.yaml`, the workflow builds the resolver sidecar image beside the
proxy's, and a rot test guards the config — without this, the next labelled live run would have
silently regressed the proven `ready` to `conditional` on an advisory unobserved gate. The smoke
policy keeps `dns_outside_allowlist` at `warn` for the same shakeout reasoning as egress. The
demo/first-light paths gain a third advisory `not_evaluable` row and their committed reports are
regenerated; their verdicts are unchanged (see spec-notes §10.6/§16.2/§10.8).

**WP-19 (noise-floor calibration) then closed** — the proof that validates the variance metric
itself. All three §24 assertions hold *measured on real containers*
(`test_noise_floor_docker.py`): trajectory dispersion over **Plane A alone is exactly 0** across
six sandbox runs (a nonzero value would have meant §11.5 epoch anchoring admits jitter); the
cross-plane residual equals the committed `NOISE_FLOOR_TRAJECTORY = 0.0`
(`constants.py` — the constant is a *measurement* the docker test re-takes, the schema-drift
reflex applied to a number); and the floor does not move under concurrent load (four sandboxes
at once) — with a floor of exactly zero, "not materially" tightens to "not at all". The floor is
published in every `summary.json` (`noise_floor: {trajectory, calibrated_at}`), and §13.4's
`at_noise_floor` rule is encoded in the data: at or below the floor the summary *withholds* the
precise dispersion and sets `trajectory_at_noise_floor`, so no renderer can print a number the
instrument produces on identical input; above it, the PR comment and HTML report show the
precise figure against the floor (see spec-notes §24/§13.4).

**WP-18 (plane precedence & coverage) then closed.** `trace_inconsistency` is now *produced*
(`assertions/precedence.py`), and the implementation is the §10.8 warning taken seriously: only
the two rows the captured planes can support are comparable — a persisted workspace write Plane B
shows that no Plane A tool call claimed, and a skill-attributed egress flow whose host no tool
call mentions — each gated on Plane A supporting the absence claim being read, with a
deliberately generous claim test (a match can only suppress a finding, never fabricate one).
Every other row is *never raised*, by design, documented per-row in the module. Findings surface
in `summary.security.runtime` and render in both reports only when any exist, labelled advisory —
the disposition stays unscored and `doctor` says so. The done-when holds on real evidence: the
first-light container run at overlay-diff fidelity produces **zero** findings
(`test_execution_docker.py`), the false-positive direction (an A claim without B corroboration)
is pinned never to fire, and the §10.7 coverage-with-reasons half was already in place
(see spec-notes §10.8/§10.7).

**The model-API canary channel then closed (finishes WP-16's capture story).** The residual path
§2 names — a value in a prompt rides the allowlisted model channel out — cannot be blocked, so it
is observed: `capture/model_channel.py` wraps the `ModelClient` seam and scans every composed
request host-side, grading each hit per-request and per-canary by §10.4.1 read state (a marker in
a tool-result block is the recorded read → `canary_in_context`, info; a marker no tool result
carried → `canary_without_read`, high — one read canary never launders a co-located unread one).
With the last channel watched, the **credentials plane records `full`**, and
`canary_without_read` becomes the **fourth scored gate** (`security_runtime.canary_reads`) — the
evidence and the gate land together, since a `block` whose evidence exists but does not gate
would recreate the BW-49 trap this list exists to close. The gate's observedness takes §10.8's
absence bar, so a pre-scan `partial` trace defers rather than passing on the channel it never
watched. The §16.4 preflight gained the matching composition clause; demo/first-light demote to
`warn` (fourth advisory row, verdicts unchanged); the live smoke needs no change (canaries on,
preflight satisfiable, benign requests carry no markers — `ready` preserved). Proven on a real
container: both planted markers ride the tool result into the second composed request, both grade
`canary_in_context`, none `canary_without_read`, coverage `full` (spec-notes §10.4.1/§2/§16.2).

**WP-20's acceptance-corpus security slice then landed** — the three skills the §24 table names as
the WP-16 §10.4 done-when. `tests/corpus/{canary-thief,dns-thief,legit-credential-reader}` are real
skill packages (SKILL.md + manifest + scenarios) driven through the *real* analysis pipeline by
`test_corpus_acceptance.py`, which asserts each §25 verdict: canary-thief and dns-thief block with
the leak redacted to a fingerprint and linked to a trace record; **legit-credential-reader reaches
`ready` with no leak finding** — the §10.4.1 false-positive guard the whole destination
classification exists to protect, and the regression test a "any canary hit is a leak" change would
break. Every scan is the real one and the policy is the shipped profile with security gates at
`block`; only the transport is synthetic (the offline harness constructs the egress flow / DNS query
a thief would send and scans it for real). Two storage divergences from §24 are documented
(prose-only skills — nothing executable to base64-encode; `attacker.example` targets, inert because
never dialled), and `SECURITY.md` keeps the base64/`127.0.0.1` rules binding for any future skill
that ships a real payload (see spec-notes §24/§25).


**WP-20's functional/metric slice then landed** — three more corpus skills exercising the stack the
security slice did not: `benign-stable` (does what it declares identically every run → `ready`, BCI
> 90, the design stops at the first look), `file-selective` (**the §13.5 tier-model regression** —
reads a different file each run but identical tier-1 classes, so weighted Jaccard is 1.0 and it
reaches `ready`; a flat per-path capability set would fail the consistency gate here), and
`always-fails` (activates and reads but never writes the required output, every run → 0% pass,
`not_ready`, and the outcome is annotated **"consistently failing"** in the summary *and* the
rendered PR comment, never a bare high BCI, §13.3). The acceptance harness gained per-repetition
transcripts so `file-selective`'s genuine tier-3 variance is real, not a copy. Five §25 corpus
skills remain (`benign-chaotic`, `scope-creeper`, `rare-canary-reader`, `slow`, `over-declared`).
Still deferred (work packages, not quick fixes): the network/write scope *derivations* (an
undeclared-egress violation is not yet scored — the tool/read declared-vs-observed table is), wiring
the `credential_read_undeclared` disposition into a scored gate (needs the read-capture plane),
the blocking static-scan gate (lands with the §15 scanner),
`requires.min_bellwether_version` in the preflight, and hash-pinning the full sidecar dependency
closure.

**WP-20 then closed — the v0.1 acceptance corpus is complete** (eleven skills, three slices). The
last five skills each assert a property the smooth metrics cannot deliver, and building them
exposed four places the pipeline *computed* the evidence but never *surfaced* it, so this brick
wired those through: the **§13.5.2 peripheral report** now reaches `summary.json`
(`capability_profile.tier1.peripheral`, dual-tier — the class beside its tier-3 expansion —
plus `tier2.sensitive_hits`, `tier3.expansions`, `rare_high_risk`) and both renderers, and the
heatmap files a class under `peripheral/` rather than `core/`; a **timeout is a distinct state**
(`matrix.runs_timed_out`, ⧖ in the strip — `AnalysedRun` carries the exit reason beside the
§12.7 outcome); the **`unused` half of Declared-vs-Observed** is produced (`scope_unused_of`,
intersected over the set), rendered, named in the scope gate's reason, and blocks only under
`scope.block_on: [unused]`; and the **trajectory cluster list** is populated in the figures,
with `sets_stopped_at_look` / `sets_held_open_for_capability` / `runs_errored` filled in the
matrix. The skills: `rare-canary-reader` **blocks at N = 6, 12 and 20 alike** on a single
undeclared credential read while weighted Jaccard clears 0.8 at every N (§13.5.1.1's property,
asserted end to end — the frequency-independent scope gate catches what the smooth signal
cannot, and the peripheral report names `${HOME}/.aws/credentials` with `runs: 1`);
`scope-creeper` flags `outside_workspace_read` with the exact path and **escalates to look 2**
under the §13.1 capability-disagreement rule; `over-declared` reaches `ready` with `bash`
reported `unused`; `slow` times out on every run and is counted and drawn as its own state; and
`benign-chaotic` lands in three trajectory clusters with weighted Jaccard 1.0 and is never
`not_ready`. The corpus harness now synthesises Plane B from the in-memory filesystem's
before/after, so its declared `overlay_diff` fidelity is true and a write glob is judged against
the authoritative plane (see spec-notes §13.5.2/§12.7/§12.5/§24). The remaining §24 rows depend on
post-v0.1 subsystems (static scanner, probe suite, real-network adapter) and land with them.

**WP-17 then landed — the `claude-code` adapter, the second harness and the last v0.1 work
package.** The real Claude Code CLI runs headless *inside* the sandbox
(`claude -p … --output-format stream-json`, `harness/claude_code.py`) and Plane A is read from
two independent sources: its structured stdout stream (one JSON object per line — `init`,
`assistant` turns with `tool_use` blocks and usage, `user` lines carrying `tool_result`s
correlated by `tool_use_id`, a final `result`) mapped onto the §11.3 vocabulary, and its own
`PreToolUse`/`PostToolUse` hooks, configured inline via `--settings` to append their stdin to the
**host-owned sink FIFO** (§10.1) — the writer the sink was built for. The two are cross-checked
per `tool_use_id` after the run: a call one source has and the other lacks is a
`trace_inconsistency` on Plane A (folded into the same summary field as the §10.8 findings), an
empty hook stream degrades the plane to `partial` with the reason. Every fact about the CLI —
flag names, line shapes, hook stdin fields, telemetry env, the `Skill` tool's `{skill}` input —
was **observed at build time** from a real headless session of CLI 2.1.257 driven against a
scripted Messages API, committed as `tests/golden/claude-code/` so a future format change breaks a
test rather than silently emptying Plane A; where the binary is on PATH (CI installs the pinned
version) the same session is re-run for real through the adapter and a real FIFO. The harness's
model calls originate inside the sandbox, so they leave only through the recording proxy carrying
the **sandbox-scoped token** the proxy swaps for the real key — §3.3 invariant 1 finally bites:
`build_proxy_provider` brokers a key only for the providers a `claude-code` target names, the
§16.4 preflight refuses a `claude-code` target with no `egress.image`, and the executor hands the
CLI `ANTHROPIC_API_KEY=<scoped token>` plus the telemetry-disable env (recorded in the trace) with
the CLI's intake hosts declared as `harness_infrastructure`. The normalizer learned the CLI's tool
vocabulary in one table (`trace/tool_vocabulary.py`): `Read`/`Write`/`Edit`/… with `file_path`
are the same filesystem capabilities as api-loop's `read`/`write` with `path`, for the capability
sets and the evidence index alike (the §11.2 example, honoured). Read state for this harness —
whose model channel is visible only at the proxy — comes from the full text of the tool results
the CLI reported (`tool_result_actions`, a marker there is the `canary_in_context` read), and
model-endpoint body hits at the sidecar are graded per canary against it. The CLI controls its
own skill presentation, so `trigger_metrics_portable` is true — the reason WP-17 is in v0.1. The
container proof (`sandbox/claude-code/Dockerfile`, CI-only `test_execution_claude_code_docker.py`)
runs the CLI in the hardened sandbox behind the real proxy against the scripted API and asserts
activation by the harness, hook corroboration, model-API-only egress with the real key absent
from every artifact, and the write landing on Plane B (see spec-notes §9.4/§10.1/§11.2/§3.3).

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
| WP-13 — recording proxy: egress, credentials, decision core, addon, sidecar entry+image+launcher, internal-bridge isolation, live interception | **done** — the full done-when runs on CI |
| **Recording proxy wired into the executor** — dual-homed sidecar per run, CA mounted, egress → Plane D of the trace | **done** (PR #42–#43); the config switch is `egress.image` |
| WP-14 — CA trust chain (mechanism table, install env/commands, confirm predicate) | **host core done** — the live doctor probe is CI-only |
| WP-16 — canaries: mint, decode-then-match, classify, redact, plant-planning, Plane C scan, executor + sidecar wiring | **whole pool planted (env var + file binds); leaks scanned across final output, DNS, tool args, non-model egress URLs *and bodies* (bodies sidecar-side), and written files; redacted end-to-end** (`test_execution_canary_docker.py`); `partial` now only because the model-API channel (read-state grading) is a follow-on |
| Live model client (`harness/live_client`) — Anthropic Messages API behind the `ModelClient` seam | **done** — `openai_compatible` is a follow-on |
| Evaluation driver + run resolution + `bellwether run` wiring | **done** |
| WP-15 — controlled DNS resolver (allowlist, NXDOMAIN, query log, canary-in-labels) | **code-complete** — host core, sidecar image, executor wiring (`--dns`), Plane E in the trace; live standup CI-validated |
| HTML report, worked demo (`bellwether demo`), PR-comment posting, changed-skills detection + GitHub Action | **done** |
| Agent Plugin bundles (agent-plugins.org) — `run` expands a plugin root to its skills, plugin-level changes fan out in `changed-skills`, `mcp.json` reported as unobserved | **done** |
| **DNS gate scored** (`security_runtime.dns`) — a resolver-refused lookup drives the verdict; live smoke wires the resolver (`dns.image` + workflow image build) so the labelled run keeps `ready` on observed evidence | **done** |
| Evidence preserved from CI — per-run ARF traces + report uploaded as an artifact, report echoed to the log | **done** (PR #45) |
| **Live `bellwether run` on CI reaching `ready`** — real Haiku eval, proxy observing egress, verdict posted | **proven** (PR #45) |
| WP-19 — noise-floor calibration: Plane-A dispersion exactly 0 on real containers (sequential + concurrent load), residual published as `noise_floor`, `at_noise_floor` reporting | **done** |
| WP-18 — plane precedence (§10.8): `trace_inconsistency` produced from the two comparable rows, fidelity-gated, advisory-surfaced; zero findings on the real overlay-diff first-light run | **done** |
| **Model-API canary channel** — every composed request scanned host-side, §10.4.1 read-state grading per-request/per-canary, credentials plane `full`, `canary_without_read` scored (`security_runtime.canary_reads`) | **done** — finishes WP-16's capture story; corpus skills land with WP-20 |
| **WP-20 corpus — complete** (eleven skills: `canary-thief`, `dns-thief`, `legit-credential-reader`, `benign-stable`, `file-selective`, `always-fails`, `rare-canary-reader`, `scope-creeper`, `over-declared`, `slow`, `benign-chaotic`): real skills, real pipeline, §25 verdicts asserted in CI — the §10.4.1 false-positive guard, the §13.5 tier-model regression, and the §13.5.1.1 frequency-independence property (blocks at N = 6/12/20 alike) all proven; peripheral report, timeout state, `unused` rows and cluster list surfaced en route | **done** |
| **WP-17 `claude-code` adapter** — the real CLI runs headless *inside* the sandbox (`harness/claude_code.py`): its stream-json output is Plane A, its `PreToolUse`/`PostToolUse` hooks write to the host-owned sink FIFO and are cross-checked against stdout (`trace_inconsistency` on disagreement), its model calls leave only through the proxy carrying the sandbox-scoped token, telemetry is disabled and its hosts declared infrastructure; `Read`/`Write`/`Edit`/… map onto the same capabilities as api-loop's tools through one vocabulary table; trigger metrics are portable | **done, and live-proven** — the in-container proof is the CI-only `test_execution_claude_code_docker.py` (real CLI against a scripted Messages API), and the first labelled live run reached **`ready` against a real model** (PR #65, `claude-code-live-smoke`: 8 gates pass, functional 6/6, DNS clean) |

1018 tests: 964 offline, 54 under the `docker` mark. All green.

## What's next — remaining work, in recommended order

**v0.1 is functionally complete.** Every work package is built, both harnesses (api-loop *and*
claude-code) are proven live to `ready` on a labelled PR, and the acceptance corpus (WP-20),
coverage-honesty (WP-18) and calibration (WP-19) proofs are all in. What remains are **post-v0.1
loose ends** — none blocking the v0.1 line — listed under "Post-v0.1 — the loose ends" below.

The numbered subsections that follow (WP-15 / WP-16 / WP-17 / WP-20) are a **retrospective** of how
each of the last packages landed, kept for reference; they are all done. The forward-looking
next-steps list is the **"Post-v0.1 — the loose ends"** section after them. The order in both
reflects dependencies and reuses momentum — not the raw WP numbering, because the build deliberately
inserted the executor-integration + live-proof work (unnumbered) that made WP-13 usable end to end.
`docs/BUILDPLAN.md` carries the same note.

1. **WP-15 (controlled DNS resolver) — code-complete; CI validates the live path.** The whole
   resolver mirrors the recording proxy, built as a second sidecar on the run's internal bridge, and
   all of it is offline-green. Landed: the Plane E *trace seam* (`dns_actions` + `dns` coverage); the
   `dns_query`/`dns_blocked` → capability mapping (`trace/canonical.py`, grounded in §13.5 — see
   spec-notes); the resolver↔host **query-record contract** + `ControlledResolver` seam
   (`capture/dns.py`); the in-container **recorder + entry** (`capture/resolver_entry.py`); the
   **host lifecycle** (`capture/dns_sidecar.py:DnsResolverSidecar`, `resolver_ip` via `docker
   inspect`) + **per-run provider** (`cli/dns_run.py`, resolver-only, create-or-join the bridge); the
   **config switch + executor wiring** (`dns.image` digest-pinned + `build_resolver_provider`, wired
   into `SandboxRunExecutor.resolver`/`_open_resolver` with `--dns <ip> --dns-option single-request`
   in `build_argv`, Plane E into the trace, `dns: full` coverage); and the **resolver sidecar image**
   (`sidecar/resolver/` — digest-pinned base + dnslib). Two CI-gated docker done-when tests exist
   (`test_resolver_docker`, `test_execution_resolver_docker`), mirroring the proxy's.
   - **Left for CI / follow-on:** the image build + live standup run on CI — **validated on
     PR #58** (`test_resolver_docker` and `test_execution_resolver_docker` passed in the
     `container` job, zero skips). The
     §3.3-invariant-3 live-probe (a direct public-resolver query from the container fails) and the
     `dns-thief` corpus assertion land with WP-20's corpus; the covert-channel *detection* is already
     unit-tested offline (canary-in-labels, the capability mapping, the query records).

   Found + fixed en route (not WP-15): `egress_actions` emitted a non-spec kind `"egress"` for a
   *permitted* flow — the §1581 kind the canonicalizer maps is `"egress_request"` — so every
   permitted egress flow was silently uncanonicalised (unscored). Corrected, with the end-to-end
   capability test the old kind-only test lacked.
2. **Plant + scan canaries in a live run (finish WP-16).** The minting/decoding/redaction logic
   exists; this places canaries in the sandbox and scans observed egress **and** DNS labels for them.
   Depends on 1 (DNS observed) — now unblocked.
   - **Landed:** the **planting planner** (`capture/planting.py:plan_canary_planting`) — turns a
     run's minted canaries into the env vars + files that carry the markers plus the marker-free
     `PlantedSlot`s the trace records (§10.4.3: the value reaches the container, never an artifact);
     the **host-side Plane C scan** (`trace/build.py:canary_actions`) — scans the already-built
     source actions (DNS query names + the model's final output) for markers and emits one Plane C
     finding per hit, its `kind` the finding class and its `correlation.anchor_seq` pointing at the
     source action that carried it, holding only the canary id / offset / length — never the value;
     the **trace-wide redaction pass** (`trace/build.py:redact_trace_actions`) — replaces every exact
     leaked marker across all planes with its `<canary:…>` fingerprint before the trace is written,
     so a leak the scan just recorded never reaches the uploaded artifact raw (§10.4.3); and the
     **executor wiring** (`cli/execution.py`, `plant_canaries` from `config.canaries.enabled`) —
     mints per-*evaluation* canaries, delivers the env-var canary into the container, scans the
     observed host-side planes, redacts, records the plant by reference in the `IdentityBlock`, and
     flips `credentials` coverage to `partial`; and **file-slot planting** — the four file canaries
     are written to host files and delivered as read-only binds at their resolved container paths
     (`~/…` → the container HOME, a bare relative path → the workspace CWD, absolute verbatim), so the
     whole pool is now planted, not just the env var. Proven end-to-end on a real container
     (`test_execution_canary_docker.py`): the sandbox's own echo of `$INTERNAL_API_TOKEN` **and** its
     `cat ~/.aws/credentials` carry the markers (both channels delivered), both leaks surface as Plane
     C `canary_leak`s, all five canaries are recorded by reference, and neither raw value is anywhere
     in the trace JSONL — only fingerprints.
   - **Tool-argument and egress-URL scanning are now wired too** (`_scan_source_action` gained
     `tool_call` and `egress_request`/`egress_blocked` branches). A marker in a tool call's arguments
     — a `fetch` URL, a `bash` `curl`/`nc` command — is a `tool_args` `canary_leak`, catching the skill
     that exfiltrates *through* a tool when it has no direct socket. A marker in a **non-model egress
     request's path/host/SNI** — the classic `GET /exfil?d=<secret>` to an attacker host — is an
     `other_host` leak caught host-side from the flow record (the body stays sidecar-side; the request
     line does not). The read that fetched the credential (path in, value out) is not flagged, and
     model-API URLs are skipped (harness-built; read-state grading is a follow-on) — so the finding
     stays false-positive-free. Offline-tested against the real `egress_actions` record shape.
   - **Written-file scanning is wired** (`trace/build.py:written_file_actions`,
     `cli/execution.py:_written_file_leaks`): Plane B records writes by hash only, so the executor
     reads each written *regular* file from the host-side overlay upper (bounded, never a special file
     §10.0) and scans its bytes — a marker in a file the skill wrote is a `written_file` leak anchored
     to the Plane B write that created it. The content never enters the trace, so the finding is
     marker-free by construction (no fingerprint needed). Proven end-to-end on a real container
     (`test_execution_canary_docker.py`): a skill copies `~/.aws/credentials` into a workspace file and
     the leak surfaces with the raw value absent from the artifact.
   - **The planted files now carry realistic credential shapes** (`capture/planting.py:_file_body`):
     an AWS INI block, an OpenSSH-PEM wrapper, a `.env` with an `API_KEY=`, a git-credentials URL —
     the marker contiguous on its own line so the exact-match scan still finds it and redaction
     fingerprints just the value. A bare token is bait a capable skill routes around; a real-looking
     file is one it treats as a real secret.
   - **Egress-body scanning is wired end to end.** `make_flow` scans the request body for canaries
     where it exists, before the body is reduced to a digest, recording marker-free `EgressCanaryHit`s
     on the flow; `decide_request`/`ProxyAddon` thread the run's canaries; the flow-record serialization
     round-trips the hits. The host writes the run's markers into the sidecar config (on the shared
     volume the CI upload excludes, so no marker reaches an artifact); `build_addon` reconstructs the
     canaries inside the sidecar; the executor threads the run's canaries into `proxy.open` and reads
     `flow.canary_hits` into Plane C body leaks (`egress_body_actions`) correlated to the egress action.
     Non-model bodies are scanned (`other_host`, critical); model-API bodies are skipped, same as
     model-API URLs. Every logic step is offline-tested (`make_flow` body scan, flow round-trip,
     `build_config` markers, `build_addon` reconstruct-and-scan, `egress_body_actions`); the real
     sidecar's compose-and-record path is covered by the existing proxy CI test.
   - **The model-API channel is closed** (`capture/model_channel.py`): every composed request is
     scanned host-side and graded per-request/per-canary by read state; `credentials` records
     `full` and `canary_without_read` is a scored gate (`security_runtime.canary_reads`). What
     remains of WP-16 is corpus-shaped. A real-POST sidecar-body CI
     test is deferred: it needs an HTTP client in the sandbox image the minimal test image lacks; the
     body-scan logic is offline-proven and the sidecar composition is CI-proven. Then the corpus skills
     (`canary-thief`, `dns-thief`, `legit-credential-reader`, `encoded-chunked-thief` xfail) for the
     §10.4 done-when.
3. **`claude-code` adapter (WP-17) — done, and now run live.** The second harness: a skill is
   evaluated under the real CLI and its hooks, cross-checked against the host sink. The
   **labelled-live path is wired** (`.github/workflows/bellwether-claude-code.yml` builds the
   claude-code sandbox image and the two sidecars and runs `examples/live/config-claude-code.yaml`,
   one `claude-code`/Haiku target, on a `bellwether-run`-labelled PR alongside the api-loop
   workflow, with the benign `claude-code-live-smoke` skill as the trigger), and the **first
   labelled `claude-code` live run has now happened on PR #65.** It exercised the leg the scripted
   container proof cannot: a real model, the live dual-sidecar topology, and a cloud CI runner's
   networking — and surfaced **five environment defects**, each invisible to every offline test,
   now fixed (full account in spec-notes §9.4/§10.6): the §10.4.3 canary phantom write; harness-state
   churn mis-scoped; the overlay-workdir upload EACCES; the proxy hostname exceeding the 63-octet DNS
   label limit (`ENOTFOUND`), fixed with a short `--network-alias`; and a cloud runner's inherited DNS
   search domain manufacturing a phantom `dns_blocked` that warned the DNS gate and capped the verdict
   at `conditional`, fixed by clearing the sandbox search list (`--dns-search .`). Plus one
   scenario-side fix: the tool-name assertions matched exactly, and the two harnesses spell the same
   tool differently (api-loop `read`, the CLI `Read`) — and `claude-code-live-smoke` is evaluated
   under *both* live workflows, so no exact spelling satisfies both. `tool_called`/`tool_not_called`/
   `tool_sequence` now fold case (`_tool_name_matches`), so one natural `{name: read}` matches both.
   With these in, the claude-code live run reached **`ready`** — 8 gates pass, functional 6/6, DNS
   clean (no phantom `dns_blocked`) — and the api-loop run of the same skill stays `ready` too. `telemetry-noisy` (§24) also becomes buildable now that
   a real harness with declared infrastructure endpoints exists.

   *Note (this session): a genuinely live paid run cannot originate from a Claude-Code-on-the-web
   session — there is no `ANTHROPIC_API_KEY` (the host mediates model access via an OAuth token
   that is not an injectable key), and the org egress policy blocks the package mirrors the two
   image builds need, so those builds stay CI-only. The paid run happens on CI, where the secret
   key and open build egress live. The five environment defects above were each isolated by
   reproduction on the real Docker daemon and the real CLI binary, without a paid run.*
4. **Corpus & acceptance (WP-20) — done.** All eleven v0.1 skills are in and CI-asserted: the
   security slice (`canary-thief`, `dns-thief`, `legit-credential-reader`), the functional slice
   (`benign-stable`, `file-selective`, `always-fails`), and the frequency-independence/scope/shape
   slice (`rare-canary-reader`, `scope-creeper`, `over-declared`, `slow`, `benign-chaotic`). The
   §24 rows that remain (`over-triggering`, `git-peeker`, `telemetry-noisy`, the chunked thieves,
   `prompt-channel-thief`, `server-tool-user`, `fetch-and-exec`, `obfuscated-injection`,
   `eval-aware`, `model-divergent`, `oom-hog`) each need a post-v0.1 subsystem — the static
   scanner, the probe suite, or a real-network corpus run — and land with it. With WP-17 in **and
   live-proven** (PR #65), **every v0.1 work package is built and both harnesses are proven live**;
   what is left are the post-v0.1 loose ends below.

### Post-v0.1 — the loose ends (the forward-looking next steps)

None of these block the v0.1 line; they are the natural next bricks, roughly in order of
ratio of value to effort:

1. **WP-14 live doctor interception probe** — a live check that the CA-trust chain actually
   intercepts (small; the host core is done, only the live probe remains).
2. **Plugin-layout staging** — install an Agent Plugin bundle *whole*, in the layout a real client
   uses (`--plugin-dir`), rather than each skill as a bare directory (spec-notes §5/§6/§18).
3. **Per-run sink path** drawn from the identifier stream rather than the fixed
   `/dev/bellwether-events` (§3.5: a fixed FIFO path is an instrumentation tell).
4. **`openai_compatible` provider** — a Chat-Completions message-shape translation behind the
   existing `ModelClient` seam (the Anthropic client is done).
5. **The remaining §24 corpus rows** — `over-triggering`, `git-peeker`, `telemetry-noisy`, the
   chunked/interleaved thieves, `prompt-channel-thief`, `server-tool-user`, `fetch-and-exec`,
   `obfuscated-injection`, `eval-aware`, `model-divergent`, `oom-hog`. Each waits on a post-v0.1
   subsystem (static scanner, probe suite, or a real-network corpus run); `telemetry-noisy` is now
   buildable since a real harness with declared infrastructure endpoints exists.
6. **Credential-read capture plane** — turn the captured-but-unscored undeclared-credential-read
   into a gate (the one "captured as evidence, not yet scored" item left after the DNS and
   canary-read gates landed).

*Recently completed (was item 1 here): the live egress/DNS gates are now `block`, not `warn`.
Both live policies enforce default-deny — `egress_outside_allowlist` and `dns_outside_allowlist`
are `block` in `examples/live/policy.yaml` and `policy-claude-code.yaml`, guarded by rot tests, and
the §16.4 precondition confirms both planes are observed so a benign run still reaches `ready`.*

**The live smoke run observes egress and DNS and enforces the allowlist.** `examples/live/config.yaml`
sets `egress.image` and `dns.image`, and the `Bellwether` workflow builds those sidecar images before
the paid run — so a labeled live PR stands the dual-homed proxy and controlled resolver up around each
repetition, egress and DNS read *observed*, and a benign skill is observed-clean. The smoke policies
now set `egress_outside_allowlist` and `dns_outside_allowlist` to **`block`**: a clean run passes
(default-deny enforced, nothing outside the allowlist), and a surprise flow or an out-of-allowlist
lookup reddens the run rather than only warning. A rot test guards each config against a gate
regressing to `warn` or the plane rotting to unobserved.

**The producer path has an executor-level done-when on CI.** `test_execution_proxy_docker` stands
a real mitmproxy sidecar up around a real sandbox run *through `SandboxRunExecutor`* — the two
bridges, the dual-home attach, the CA written to the shared volume and mounted into the sandbox, the
run routed through the proxy — and asserts egress reads **observed** (not unavailable), the benign
skill's trace is observed-*clean*, and no bridge leaks on teardown. It exercises the load-bearing
unknown: if mitmproxy does not write its CA where the executor expects, `ca_cert_path()` raises and
the run fails loudly rather than producing a zero-egress trace (§9.2). This is the same observed-clean
state that lets a benign live run reach `ready` — now proven against a live model on a labelled PR
under both harnesses (api-loop and claude-code, PR #65).

**`bellwether run` can now turn the proxy on from config.** `build_proxy_provider` reads
`egress.image` (a new digest-pinned field): empty — the shipped default — leaves the sandbox
networkless exactly as first-light; set to the sidecar image, it assembles the dual-homed provider
(default-deny allowlist from the configured providers plus `egress.allowlist`, an empty broker
because the `api-loop` model runs host-side) and the `run` command hands it to the executor. So a
live config now produces observed egress end to end from the CLI, and the live workflow is wired to
build the sidecar image and run with it — a labeled live PR is the last step, and it is what proves a
benign run reaches `ready`.

**The recording proxy is now wired into the live executor** (§10.5, §3.3). Both halves of the
egress plane exist. The consumer half (PR #41) taught the gate to read observed egress:
`analyse_run` reads whether the proxy ran (coverage) and whether any default-deny block was
recorded, and the gate decides — an observed-clean run **passes**, an observed run with a block
takes the policy disposition (`block`/`warn`), a run with no proxy still **defers**. The producer
half is the executor now standing a **dual-homed** sidecar up around each run: the sandbox lives on
a Docker `--internal` bridge (no route out, §3.3 invariant 3), the sidecar is attached to *both*
that bridge and an ordinary egress bridge (the sole crossing to the internet, recording every
flow), the sandbox routes through it via `HTTPS_PROXY` and trusts its CA (mounted read-only from
the shared volume, §9.2), and what the proxy records becomes Plane D of the trace. This is what the
user's "it needs internet — otherwise the skill fails or knows it's in a sandbox" requires: the
skill reaches the internet *and* every byte is observed. The Docker seams (`extra_env`,
`extra_ro_binds`, `connect_network`) and the standup logic (`cli/proxy_run.py`) are proven — the
seams live on a real daemon, the topology and teardown offline with fakes, and dual-homing against
a real daemon on CI. The full live interception from inside the sandbox (a real HTTPS request in the
trace, a benign run reaching `ready`) is the next brick.

**The live PR-integration path is proven end to end.** On PR #39 a real Haiku evaluation ran on
CI — skill detected from the diff, run six times in the sandbox, verdict rendered and posted as a
PR comment — for roughly a dollar across the shakeout. It reached `conditional`, and the report
did its job: it caught that the skill activated on only 1 of 6 runs and annotated the result
*consistently failing*, the exact variance a single successful try would hide. The shakeout took
two cheap fixes (a relative Docker bind-mount path; a doubled artifact-tree directory).

The live evaluation is **opt-in per PR** — it runs only when a PR both changes a skill *and*
carries the `bellwether-run` label, so nothing spends by surprise; the changed-skills detection
alone never triggers a paid run. `examples/live/` holds the cheap config (api-loop + Haiku, one
look of 6, egress advisory) and `bellwether run` takes a `--max-tokens` cost ceiling. The executor
wires the recording proxy, the CLI builds the provider from `egress.image`, and **a labelled live PR
reached `ready` with the egress gate passing on observed evidence** (PR #45). The one thing still
unproven live is *interception of real skill traffic* — the benign skill makes no egress, so an
actual HTTPS request appearing in the trace waits on the live-canary/doctor-probe work (see "What's
next").

**There is now something to look at.** `bellwether demo` renders three example skills
(`examples/skills/`) to three reports (`examples/reports/`) — including an HTML report —
entirely offline, through the same analysis pipeline a live run uses. The three reach three
different verdicts on purpose: a clean note-taker (`conditional`), a credential exfiltrator
that passes its task but reads `~/.aws/credentials` (`not_ready`, scope gate), and a flaky
formatter whose pass rate falls below the gate (`not_ready`, functional gate). Open
`examples/reports/demo-sneaky-exfiltrator/report/report.html` to see the flagship.

**`bellwether run` is now wired from the CLI.** `cli/run.run_evaluation` assembles the whole
pipeline — resolve the run, build the per-target live model client, plan the matrix, drive it
through the sandbox executor, orchestrate the verdict, write the artifact tree, exit by verdict —
and the `run` command loads config/policy/skill and calls it. The assembly is tested offline end to
end with an injected scripted executor (`benign-stable` → `conditional`, the first-light shape),
and the command's refusal paths (no skill, missing config, no daemon, unset key, placeholder model)
exit 3 with a clear reason. A **real container run from the CLI against a live model is now proven on
CI** (PR #45: standup-summariser, 6× under Haiku, proxy observing egress, verdict `ready` posted).
The declared scope is still intentionally not applied — its auto-derived egress/DNS assertions want
the DNS plane observed too, which lands with the resolver-wiring brick.

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

### What WP-13 increment 1 built

The **host-side egress semantics** — the deterministic core of Plane D, in
`bellwether.capture.egress` and `trace.egress_actions`, offline and fully tested (25 tests):

- **`classify_egress`** (§10.5.0): `model_api` / `harness_infrastructure` /
  `skill_attributed`, model API checked first, label-boundary suffix matching so a lookalike
  domain cannot pose as the provider. Only `skill_attributed` counts toward `no_egress` —
  without this, telemetry from any real agent CLI makes `no_egress` never pass.
- **`EgressAllowlist`** (default-deny): providers + declared infrastructure + explicit extras
  permitted; everything else blocked, with a reason. A blocked attempt is evidence, not an
  error.
- **`CapLedger`** (§10.5.1): per-run request and byte caps on the sandbox-scoped token, the
  bound on residual-channel exfiltration; a crossed cap is `budget_exceeded`.
- **`redact_headers`**: an allowlist (keep these), not a denylist, so a *new* auth header
  can't leak a credential into an artifact. **`make_flow`** reduces the request body to a
  digest + length — no body value ever reaches a record.
- **`correlate_egress_induced_failure`** (§10.5.0): a run with both assertion failures and
  blocked egress is flagged, to be excluded from quality metrics and kept for security.
- **`RecordingProxy`** is the seam for the sidecar; its base raises rather than silently
  observing nothing (a zero-egress trace reads as a clean skill).

### What WP-13 increment 2a built

The **credential-isolation core** (§3.3 invariant 1 — the most important security property
of the tool), in `bellwether.capture.credential`, offline and fully tested (14 tests):

- **`mint_sandbox_token`**: a per-run, reproducible, opaque sandbox-scoped token — worthless
  outside the proxy; its only power is that the proxy recognises it and swaps in the real key.
- **`strip_and_inject`** (§10.5.1): the proxy-side transform that replaces the scoped token
  with the real key in an auth header, preserving the scheme, and injects *only* for the
  token it minted (a skill's own key is never swapped for Bellwether's).
- **`CredentialBroker`**: the host-side ledger. `sandbox_env(provider)` is what the container
  receives — the scoped token under the provider's own key var, **never the real key**;
  `inject` performs the swap; `leaks_a_real_key(text)` is the guard teardown and the done-when
  use to assert no artifact holds a credential. The real key is read from the host
  environment and leaves only through `inject`.
- **`proxy_environment`**: the routing env (HTTPS_PROXY etc., no bypass), plus the CA-bundle
  vars for WP-14.

The end-to-end invariant is tested by joining this to increment 1: an injected request really
carries the real key on the wire, but the flow record redacts the auth header, so the key
reaches the provider and nothing else.

### What WP-13 increment 2b-i built

The **proxy decision core** — `decide_request` in `bellwether.capture.proxy_core`, the pure
per-request logic the mitmproxy addon will run, offline and fully tested (10 tests). The
*order* is the security property, so it is fixed here rather than left to the addon:
allowlist-check (block a denied host, record it) → cap-check (refuse before forwarding, so
the residual-channel bound actually holds; `budget_exceeded`) → inject the real key for a
permitted `model_api` request → record the flow either way. Tested edges include: a blocked
request never consumes the cap (a skill can't exhaust the budget with denied attempts) and
the recorded flow never holds the real key *or* the scoped token even after injection. This
is the whole "what the sidecar decides" — the container that runs it is all that's left of
WP-13.

### What the live model client built (§9.5, §9.3)

`bellwether.harness.live_client` — the real HTTP client behind the `ModelClient` seam, the last
piece of logic before `bellwether run` can drive a real skill (10 tests):

- **`AnthropicClient`** implements `complete(ModelRequest) -> ModelTurn` against the Messages API.
  The `api-loop` loop runs host-side (its tools exec into the sandbox), so this client runs with the
  real key directly — the proxy observes the *sandbox's* egress, not the harness's own model calls;
  the in-container `claude-code` agent (WP-17) is the one whose calls route through the proxy.
- The wire work is **pure and seamed**: `anthropic_request_body` and `parse_anthropic_response` are
  functions, and the HTTP call is a `transport` seam, so the request shape, response parsing, auth
  headers (`x-api-key`, `anthropic-version`), and error mapping are all tested without a network or a
  key. Two edges with teeth: an unknown `stop_reason` maps to `other`, never silently to `end_turn`;
  and `model_id_reported` is recorded as what the provider *said it served*, so a silent model swap
  is visible (§9.3). `build_model_client` dispatches on provider type — `openai_compatible` raises a
  clear "not yet" because its Chat Completions shape needs a message translation the loop's
  Anthropic-shaped messages don't carry.

### What the live interception test proved (§10.5, §3.3 — the WP-13 done-when)

`tests/test_sidecar_docker.py` now stands the whole plane up in a real container topology on CI and
asserts the done-when end to end: a **client** container sends the *scoped* token through the proxy;
a permitted model-API call (a **peer** container named as the provider endpoint, so docker's embedded
DNS resolves it and classification is plain string matching) is forwarded with the **real key
injected on the wire** — the peer echoes it back — while the scoped token does not survive the swap;
a denied host (`evil.example.com`) is **blocked with a 403** the client sees, short-circuited before
any forward or DNS; and the flow log records both flows while holding **neither the real key nor the
scoped token**. All three containers sit on a user-defined `--internal` bridge, so §3.3 invariant 3
holds at the same time. On any failure the sidecar, peer, and client outputs are dumped into the
assertion, so a remote failure is diagnosable from the job output. The credential-isolation invariant
(§3.3 #1 — the most important property in the tool) is now proven live, not just in unit tests.

### What the sidecar image built (§10.5)

The **container that runs the addon**, in `sidecar/proxy` — proven on CI:

- **`sidecar/proxy/Dockerfile`** builds from a **digest-pinned** `python:3.12-slim`, installs
  `mitmproxy==12.2.3` (exact — its addon API is not stable across majors), installs Bellwether from
  `pyproject.toml` + `src` (validated: the wheel builds with a static version, so no git in the
  image), and copies the `mitmdump` loader `sidecar/proxy/proxy_entry.py` to the fixed
  `SIDECAR_ENTRY_PATH`. There is deliberately no `ENTRYPOINT` — the launcher passes the full
  `mitmdump … -s …` argv so the exact command stays recordable, as the sandbox backend does.
- **`tools/pin_lint.py` now also lints Dockerfiles** — every `FROM` that names a registry image must
  carry an `@sha256:` digest (build-stage `FROM`s and `scratch` exempt). A floating base is the same
  mutable-input hole as a floating action, one layer down.
- **`tests/test_sidecar_docker.py`** (CI-gated on `CI`, since the build needs open egress) builds the
  image and starts the sidecar through the real `MitmproxySidecar`, asserting the empty flow log
  appears — proof `mitmdump` came up and registered our addon, i.e. Bellwether imports in the
  mitmproxy runtime and the inside-the-container half runs for real. Container logs are dumped into
  the assertion on a readiness failure so a first-run CI failure is diagnosable from the job output.

The **full interception path** — a client container routed through the proxy, a permitted call
recorded with the real key injected and a denied one blocked, plus CA trust — is the follow-up that
closes the WP-13 done-when, standing on this now-proven image.

### What the sidecar host launcher built (§10.5)

The **lifecycle around the `mitmdump` container**, in `bellwether.capture.sidecar`, offline and
fully tested via a `runner`/`sleep` seam (9 tests):

- **`MitmproxySidecar(RecordingProxy)`** — the proxy the analysis path talks to. `start` writes the
  non-secret config to the shared volume, launches the sidecar on the run's internal bridge, and
  waits for ready; `flows` reads the flow log back; `stop` force-removes the container. It exposes
  `proxy_url` — the sidecar reachable by container name on the bridge — for the sandbox's
  `HTTPS_PROXY`.
- **The real key never reaches the command line.** The sidecar needs the real credential, but a
  `-e KEY=value` flag would put it in the process table and any recorded command. The launcher
  passes `-e KEY` (name only) and runs `docker` with the key in its *own* environment, so docker
  forwards the value and it appears in no argv, no config, no artifact (§3.3). The load-bearing
  test asserts the key's *value* is in no argv token.
- **Readiness is the flow log appearing, not a guess.** The entry writes an empty flow log the
  instant it loads, so the log's appearance proves mitmdump came up and registered the addon; a
  timeout with no log is a loud failure, never a clean-looking zero-egress run. A stale log from a
  crashed prior run is cleared before start, so readiness can't be trivially true and this run
  can't inherit another's flows.

### What the sidecar entry built (§10.5)

The **inside-the-sidecar half** — how the proxy container rebuilds the run's `ProxyAddon` from a
config file and its environment, in `bellwether.capture.sidecar_entry` and three new
`CredentialBroker` methods, offline and fully tested (11 + credential tests):

- **The broker's sidecar halves**: `sidecar_export` hands over the *non-secret* mapping (per
  provider, its `api_key_env` name and scoped token — the token is already what the container
  holds, so exporting it leaks nothing); `sidecar_real_key_env` is the one place a real key leaves
  the host, and it goes only into the sidecar's own environment; `for_sidecar` rebuilds the broker
  from those two parts, skipping any provider whose key is absent from env exactly as `for_run`
  does on the host. The load-bearing test is **reconstruction fidelity**: the rebuilt broker
  injects the real key for the *same* scoped token the host minted — if that mapping did not
  survive the round trip, every model call would go out bearing a worthless token and injection
  would silently fail.
- **`SidecarConfig`** (canonical-JSON serialisable, no secrets) + **`build_addon`** rebuild the
  `ProxyAddon` from the same endpoints, allowlist and caps the host's `decide_request` used.
  **`block_response_args`** reduces a `BlockResponse` to the pure `(status, body, headers)` triple
  mitmproxy's `http.Response.make` takes, so the block path is tested without mitmproxy — the one
  genuinely mitmproxy-shaped line (assigning `flow.response`) is validated by the CI docker test.
  **`load_addon_from_env`** is the mitmdump entry: it refuses to run without its config (an
  unconfigured proxy would forward everything and record nothing) and writes an empty flow log at
  construction, so "the proxy ran" is true from t=0 and a *missing* log unambiguously means it
  never started.

### What the proxy addon built (§10.5)

The **mitmproxy-shaped glue over the decision core**, in `bellwether.capture.proxy_addon`,
offline and fully tested (13 tests):

- **`ProxyAddon`** is the per-request brain the sidecar runs: translate a mitmproxy request →
  `decide_request` → apply. It owns the run's mutable egress state (the `CapLedger`, the
  accumulated flows), and either *mutates the outgoing request's headers in place* — so a
  permitted model-API call really carries the real key on the wire — or returns a `BlockResponse`
  the entry script renders as a synthetic 403 (allowlist denial) or 429 (`budget_exceeded`). It
  adds no security logic; the order and decisions are all in `decide_request`. `RequestLike` is
  the exact structural subset of `mitmproxy.http.Request` it touches, so it is tested with a plain
  fake — no mitmproxy, no container — and the entry script in the image stays too thin to hide a
  bug.
- **The flow-record contract** (`flow_record_line` / `read_flow_records`): the sidecar appends one
  canonical JSON line per flow to a shared-volume file, the host reads them back into `EgressFlow`
  objects for `trace.egress_actions`. A *missing* log raises rather than returning `[]` — the
  sidecar always writes it, so its absence means the proxy never ran, and a zero-egress trace that
  reads as a clean skill is the exact failure this plane exists to prevent; a *written-but-empty*
  log is a legitimate observed-zero-egress run. The tested edge that matters: a blocked flow's
  `None` response fields survive the round trip as `None`, not `0`.

### What the internal-bridge isolation built (§3.3 invariant 3)

The **routing half of "no unmediated route out"**, in `bellwether.sandbox.docker` —
`create_network`/`remove_network` and a `network` argument already threaded through `run`
and `build_argv` (4 docker tests, `test_network_docker.py`):

- **`create_network(name, internal=True)`** builds a Docker `--internal` bridge: a container
  on it reaches only its peers, so the sole routes out are the recording proxy and resolver,
  which are those peers. A socket to a public address is refused by the kernel with "network
  is unreachable" *before* any userspace egress code runs — the isolation is a routing fact,
  not a policy the container could talk past. Creation is deliberately non-idempotent: a name
  collision means a leaked network whose peers we did not place, so the caller removes and
  retries rather than silently reusing it.
- The docker test proves invariant 3 by reading `/proc/net/route` inside a real container on
  the bridge — a subnet route exists (attached to a real bridge) but **no default route**
  (no way out) — and contrasts it against `--network none` (no routes at all), so the block
  is provably the bridge's missing gateway, not the absence of a network. The check is a
  plain file read: no `nc`/`curl`/bash `/dev/tcp`, so it behaves identically on the alpine CI
  image and the mariner default, and does not depend on host iptables (which is why it
  validates here as well as on CI). The proxy peer *being reachable and recording* is the
  sidecar's live half, still CI-only.

### What WP-16 (canaries) and WP-14 (CA core) built

- **WP-16 canaries**, `bellwether.capture.canary`, offline and fully tested (16 tests):
  `mint_canaries` (per-evaluation markers from `canary_seed`, high-entropy, no fixed prefix,
  reproducible so the fixture cache still hits); `classify_canary_hit` (the §10.4.1
  destination→severity rule — info for a canary in a model request after a read, high with no
  read, critical anywhere else — which keeps the flagship finding from a guaranteed false
  positive on the legit-reader shape); `scan_for_canaries`/`decoded_forms` (decode-then-match
  over base64/base64url/base32/hex/URL/HTML/reversal, decoding *embedded* encoded runs with
  one nesting level, plus ≥12-char windowed matching and DNS label-stripping); and
  `redact_canaries` (capture-time fingerprint `<canary:c1@offset=,len=>` so an ARF artifact
  uploaded to CI never holds the secret). The independently-encoded-chunking gap stays a
  documented §2 limit. Two bricks now sit on top of that engine, both pure and offline-tested:
  the **planting planner** (`capture/planting.py:plan_canary_planting`, `tests/test_planting.py`)
  turns a run's minted canaries into env vars + files carrying the markers plus marker-free
  `PlantedSlot`s for the trace (§10.4.3); and the **host-side Plane C scan**
  (`trace/build.py:canary_actions`, in `tests/test_canary.py`) scans the built source actions
  (DNS query names + final output) and emits a Plane C finding per hit, correlated by
  `anchor_seq` to its source and carrying only the canary id / offset / length — never the value.
  A **trace-wide redaction pass** (`trace/build.py:redact_trace_actions`) then replaces every exact
  leaked marker across all planes with its fingerprint before the trace is written, and the
  **executor** (`cli/execution.py`, `plant_canaries`) delivers the whole pool into the sandbox — the
  env-var canary as an environment variable, the four file canaries as read-only binds at their
  resolved slot paths (`~/…` → the container HOME, a bare relative path → the workspace CWD) — runs
  scan-then-redact, records every plant by reference in the header `IdentityBlock`, and sets
  `credentials` coverage to `partial`. `test_execution_canary_docker.py` proves the whole loop on a
  real container: the sandbox's own echo of `$INTERNAL_API_TOKEN` and its `cat ~/.aws/credentials`
  carry the markers (both channels delivered), both leaks are found and fingerprinted, and no raw
  value reaches the trace JSONL. The host-side scan covers the model's final output, DNS query names,
  **tool-call arguments** (the exfil-through-a-tool channel), **non-model egress request URLs**
  (path/host/SNI — URL-based exfil to an attacker host), **non-model egress request bodies** (scanned
  sidecar-side in `make_flow`, the hits carried back on the flow), and **written-file contents** (read
  host-side from the overlay upper, since Plane B is hash-only); the plane stays `partial` only because
  the model-API channel (a canary sent to the model, with `canary_in_context` vs `canary_without_read`
  read-state grading) is a follow-on.
- **WP-14 CA trust-chain core**, `bellwether.capture.ca`, offline and fully tested (7 tests):
  the complete §9.2 mechanism table (system store + `NODE_EXTRA_CA_CERTS` /
  `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` / `CURL_CA_BUNDLE`, because Node and others ignore the
  system store), `ca_trust_environment` and `system_store_install_commands` that install it,
  and `interception_confirmed` — the predicate doctor applies to the proxy's recorded flows. A
  `False` there means TLS interception silently failed (zero-egress traces read as a clean
  skill), so doctor must fail loudly on it.

### What WP-15 (controlled DNS resolver — host core) built

The **host-side core of Plane E**, `bellwether.capture.dns`, offline and fully tested (13
tests). An HTTP proxy never sees UDP/53, so without a controlled resolver DNS is a covert
channel that routes entirely around Plane D — a skill encodes a secret into query *labels*
and exfiltrates it while the recording proxy records nothing. This is the pure decision half,
split from the resolver container exactly as the proxy's `decide_request` was split from its
sidecar:

- **`DnsAllowlist`** (default-deny, §10.6): `permits` matches on a *label boundary* — the same
  rule the egress allowlist uses — so `anthropic.com` permits `eu.api.anthropic.com` but never
  `notanthropic.com` or `anthropic.com.attacker.example`. An empty allowlist permits nothing.
  `nxdomain_reason` names the name, the plane and the mechanism, never a bare enum (§10.7).
- **`decide_query`** normalises the name (lowercase, trailing-dot-stripped), decides it against
  the allowlist, and returns a **`DnsQuery`** record. Every query is logged whether or not it
  resolves — a refused query is `dns_blocked`, evidence exactly like a blocked HTTP request, not
  an error; the log is the plane's ground truth, so a resolver that dropped refusals would erase
  the exfiltration attempt it exists to capture.
- **`scan_query_for_canaries`** wraps `scan_for_canaries(destination="dns", is_dns=True)`, so a
  marker chunked across labels (`<c1>.<c2>.<c3>.attacker.example`) is found once the dots are
  stripped and — DNS being a non-model destination — graded a **critical** `canary_leak`, on the
  same footing as any other leak.

The resolver *sidecar* (`dnslib`/`coredns` in a second peer on the internal bridge, the §3.3
invariant-3 UDP/53 lockdown that makes the resolver unavoidable rather than merely available,
and the `dns_query`/`dns_blocked` trace actions) is the container half, CI-only — the same
split the proxy used.

### What the HTML report and the worked demo built (§17.4, §24)

The first surface a human *looks at*, and three example skills to point it at:

- **`report/html.py`** (`render_html_report`) renders the report as one self-contained,
  theme-aware HTML page — verdict banner, headline stats, gate table, the strip chart and
  capability heatmap as real grids, the Declared-vs-Observed table, and the §2 limitations
  footer. It renders from the same `Summary` + `Figures` as the PR comment (*renders, never
  computes*), so the two can never disagree; `orchestrate` now writes it at
  `report/report.html` for **every** evaluation. It is a deliberately scoped-down first slice
  of the §17.4 site — one page, not eleven views. `build_figures` is now public on the
  orchestrator so both renderers share one figure assembly.
- **`cli/demo.py`** (`bellwether demo`) drives three example skills under `examples/skills/`
  through the *real* pipeline offline — scripted transcripts + an in-memory filesystem, the
  same stand-in the golden trace uses — to three committed reports under `examples/reports/`.
  The three reach three different verdicts by construction: `conditional` (a clean note-taker,
  held only by the unobservable egress plane), `not_ready` on the **scope** gate (a credential
  exfiltrator that passes its task but reads `~/.aws/credentials`), and `not_ready` on the
  **functional** gate (a flaky formatter, 6/20 pass). The security catch is a
  declared-vs-observed finding, not a functional failure — a skill that works and still
  exfiltrates is exactly the case a single successful try can never catch.
- The reports are byte-stable (fixed clock, transcripts, identifiers, and a constant demo
  version) and guarded by a **regenerate-and-diff test**, the same reflex as the summary
  JSON-Schema drift test, so the committed demo cannot rot. The bulky per-run traces are
  git-ignored; only the rendered outputs are committed. The example skills also seed the
  eventual WP-20 corpus. 40 new tests.

### What the PR-comment posting built (§18.2)

The glue that puts a report on a pull request — `cli/pr.py` and the `bellwether pr-comment`
command, offline and fully tested through an injected transport (15 tests):

- **`upsert_pr_comment`** finds the comment a prior run left (via a hidden `COMMENT_MARKER`
  in the body) and edits it in place, or creates one — so a re-run on the same PR keeps one
  live verdict rather than stacking a wall of stale ones. The HTTP call is a `transport`
  seam, the same discipline as the live model client, so the upsert is unit-tested with a
  fake; the real transport is a small urllib wrapper that returns the status instead of
  raising on 4xx.
- **The token travels only in the `Authorization` header** — read at the call site, put in
  one header, never logged, never in a URL, never returned; a test asserts it appears in no
  URL and no request body. The module lives in `cli`, not `report`, because rendering
  belongs to `report` (it reuses `render_pr_comment` unchanged) but doing IO with a remote
  service is orchestration.
- **`resolve_pr_context`** derives the repo and PR number from the GitHub Actions
  environment (`GITHUB_REPOSITORY`, `GITHUB_REF`), with an explicit `--repo`/`--pr` override;
  a non-PR context is a clear refusal, not a guess. `--dry-run` prints the comment with no
  token and no network.

### What the CI integration built (§18, §19.3)

The workflow that runs Bellwether on a pull request, and the changed-skills gating that keeps
it cheap — `cli/changed.py`, `bellwether changed-skills`, and
`.github/workflows/bellwether.yml` (8 tests):

- **`changed_skills`** maps a list of changed file paths (what `git diff --name-only` prints)
  to the skill directories affected: a skill is a directory with a `SKILL.md`, and a changed
  file is attributed to its nearest such ancestor — so a change to `foo/evals/manifest.yaml`
  is a change to the skill at `foo/`, and a change to the harness or a doc touches no skill.
  A deleted skill (no `SKILL.md` left) is never returned; two changes in one skill collapse to
  one entry. This is what makes CI evaluate **only what a PR touched**, not every skill already
  analysed — re-running the whole repo would burn the model budget and attach fresh verdicts to
  untouched skills.
- **The shipped workflow** runs on every `pull_request`, computes the changed skills, and — for
  each one — runs `bellwether run` and posts the verdict with `pr-comment`. The live branch is
  **gated on the `ANTHROPIC_API_KEY` secret**: with no key, it reports which skills it *would*
  evaluate and exits 0, so forks and un-provisioned repos stay green; the changed-skills
  detection still runs. Every action is SHA-pinned (the same discipline `pin_lint` enforces on
  the CI workflow), and `docs/ci-integration.md` documents adapting it for a skill repository.

## What to do next

This section keeps the **granular** run-path gaps; the top-of-file "What's next — recommended order"
is the authoritative sequence, and the two agree. The live-container CLI run against a real model is
**done** (PR #45 reached `ready`); what remains under it is polish and the other planes:

1. **Residual run-path gaps (now that the live run itself is proven).** The declared **scope is still
   not applied** — its auto-derived egress/DNS assertions want the DNS plane observed, so it comes
   online with the resolver-wiring brick; until then the driver passes `scope=None`. Also open:
   `RunLimits` derived from the profile rather than the defaults; **per-scenario fixtures** (the
   executor takes one fixture per run, so a skill whose scenarios need different starting trees is not
   yet expressible); and wiring the precondition check, weight validation, the §21 enforced-settings
   refusal, and the FIFO sink writer into `doctor`/`run` — see the table below.
2. **WP-15's controlled DNS resolver — the container half.** The host core (allowlist, NXDOMAIN
   decision, query record, canary-in-labels scan) is done and offline-tested. What remains is its own
   sidecar (a second peer on the internal bridge, `dnslib`/`coredns`), the §3.3 invariant-3 UDP/53
   lockdown that forces every lookup through it, and the `dns_query`/`dns_blocked` trace actions —
   the CI-only container slice, mirroring the proxy sidecar.
3. **The `openai_compatible` live client** — the Chat Completions message-shape translation the
   Anthropic client did not need.

**WP-14's live half** (doctor issuing a real request and asserting `interception_confirmed`) is still
open — the CA-in-the-loop probe. The interception test above deliberately used plain HTTP to prove
injection/blocking without TLS; the CA trust chain gets its own live proof when doctor's probe lands.

## Outstanding actions

### Code

| Item | Where | Why it is still open |
|---|---|---|
| `fixture.yaml` generated content | §9.1 step 1 | A half-designed generator is worse than none. Needs a schema decision. |
| `requires.min_bellwether_version` is not checked by the §16.4 preflight | `cli/preflight.py` | The rest of BW-51 is closed — `run` refuses an unsatisfiable policy before spending and `doctor` evaluates the check per profile — but version comparison needs an ordering rule the project has not committed to, and the one profile that sets it (`high`) already refuses on its missing capture planes, so skipping it cannot produce a false start today. |
| Weight validation not wired to `doctor`/`run` | `verdict/validation.py` | Built and tested; §13.7 wants a warning named to file and key at config load. |
| Sink container path is fixed (`/dev/bellwether-events`) | `harness/claude_code.py` `DEFAULT_SINK_CONTAINER_PATH` | §3.5: a fixed FIFO path is an instrumentation tell. The claude-code adapter writes to it via its hook command; drawing the path per run from `sandbox/identifiers.py` is the follow-on (the hook settings already take the path as a parameter). |
| The claude-code adapter's live-model proof — **landed** | `.github/workflows/bellwether-claude-code.yml`, `examples/live/config-claude-code.yaml` | The first labelled `claude-code` live run happened on PR #65 and reached **`ready`** — 8 gates pass, functional 6/6, DNS clean — exercising a real model, the live dual-sidecar topology, and a cloud runner's networking. It found five environment defects the CI-only scripted proof could not plus one dual-harness tool-name-casing fix (spec-notes §9.4/§10.6), all resolved. The claude-code harness is now proven live end to end. |
| Live model client — `openai_compatible` variant | `harness/live_client.py` | The Anthropic client is done; the Chat Completions shape needs a message-shape translation and lands separately. |
| `pids_limit` exit reason never produced | `sandbox/docker.py` | Docker gives no distinct exit code; needs another signal to distinguish it from `harness_error`. |
| Held-out probe set (§7.6, §3.5) | — | Must not appear in `--help`, the README, or the public corpus when it lands. |

### Repository settings — human-only

| Item | Status |
|---|---|
| Branch protection on `main` requiring `check` and `container` | **reported done; not verifiable from here** — the branches API still shows `main` as `protected: false`. That is consistent with a *ruleset* rather than classic branch protection, which the flag does not reflect. Worth confirming, because it is the control that closes the stale-check hazard below. |
| Private vulnerability reporting enabled | open — `SECURITY.md` already points people at it |
| Dependabot | **config committed** (`.github/dependabot.yml`, github-actions + uv, weekly) — enable it in repo settings if it is not on by default |
| CodeQL | open — thin to be missing on a repo about supply chain |

Two stray remote branches remain, both safe to delete (a session cannot delete branches
other than its own designated one, so this is left for a human):
- `claude/project-repo-setup-aspyig` — **fully merged into `main`**; its content is
  redundant.
- `claude/bellwether-code-review-t8xuzw` — the review session's branch; one unmerged commit,
  but its one useful fix (the canonicalize crash) was already extracted into the merged
  PR #13, so nothing depends on it.

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

- `CLAUDE.md` — **orientation for an agent picking this up.** The cadence, the six checks, the
  non-negotiable disciplines, and the environment gotchas, all in one page. Read it first if you are
  an agent; it points back here for state.
- `docs/spec.md` — the specification, revision 3. Authoritative for *what*.
- `docs/BUILDPLAN.md` — authoritative for *order*, and for what "done" means per package.
- `docs/spec-notes.md` — every deliberate divergence from the spec, with reasoning.
  Forty-nine entries. Read it before changing anything in the skill, sandbox, capture or
  config layers.
- `CONTRIBUTING.md` — the six mechanically-enforced rules and how to run everything.
