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
Still deferred (work packages, not quick fixes): wiring
the `credential_read_undeclared` disposition into a scored gate (needs the read-capture plane),
the blocking static-scan gate (lands with the §15 scanner),
and hash-pinning the full sidecar dependency closure.
(`requires.min_bellwether_version` in the preflight, and the network scope derivation — an
undeclared-egress host is now scored through the scope gate — have since been closed; see the
entries below.)

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

**The last disclosed BW-51 skip then closed — `requires.min_bellwether_version` is checked in the
§16.4 preflight.** It was the one precondition the wired check left out, because comparing versions
needed an ordering rule the project had not committed to. The rule is now committed in
`verdict/precondition.py` (`_parse_version`/`_version_lt`): a deliberately conservative subset of
PEP 440 — release segment of leading integers, missing components padded with zeros (`0.3` ==
`0.3.0`), any suffix (`.dev0`, `rc1`, even a `post` release) sorting *below* the bare release — so
no `packaging` dependency enters a project that hand-rolls its stats to keep the surface thin, and
an unmodelled suffix can only ever refuse a borderline start, never falsely admit one. An
unparseable minimum (`"latest"`) is itself a start-blocker rather than a silent pass. The running
version is threaded in from `cli/preflight.py` (`bellwether.__version__`) as a parameter, keeping
`check_preconditions` pure — the same pattern `available_planes` uses. The shipped `high` profile
(min `0.3`) now refuses on both the version and its missing capture planes on this v0.1 runner, the
version failure carrying a version-shaped remedy the plane failure cannot (see spec-notes §16.4).

**The two weight validators then got wired to the real paths** (§16.1, §13.7) — built and tested
since WP-11, but called from nowhere, so a mis-weighted policy was discovered late or never. The
higher-value one is the **cross-document §16.1 check** now in `run_evaluation`: a capability class
the manifest denies must not be weighted 0, because weight 0 erases it from the risk-weighted
Jaccard — the one figure feeding the BCI — so a skill could be denied a tool by its own manifest and
still post a clean consistency score while using it. Neither document can make the check alone
(policy holds the weights, the manifest holds the deny list), so it runs where both are in hand and
**refuses before a container is paid for**, alongside the §16.4 preflight; a denied tool maps to the
`tool:<name>` class the weight table names. This is the project's signature failure mode — a control
that renders clean without running — closed one more place. The **§13.7 BCI-weight check** is now a
`doctor` row: a component weighted 0 does not disable the component (that is
`metrics.components_excluded`) but silently drops it from the composite, so `doctor` warns, named to
file and key, before a run rather than after a quietly-wrong BCI. The config model already rejects a
weight set that does not sum to 1.0, so the zero-weight warning is the residual foot-gun worth
surfacing; the row reads `ok` on a clean scaffold rather than being omitted (an absent check reads
as a passed one).

**The `openai_compatible` live client then landed** (§9.5) — the last loose end in the live-client
package, previously refused as a distinct follow-on. `OpenAiCompatibleClient` translates the loop's
Anthropic content-block messages into the Chat Completions array (the system prompt → a leading
`system` message; an assistant turn's `tool_use` blocks → `tool_calls` with the input serialised to
the JSON-string `arguments` the API wants, `content` `null` when the turn is tool calls only; each
`tool_result` block → its own `tool` message keyed by `tool_call_id`, the model-assigned id kept for
correlation) and translates the response back (`finish_reason` → the neutral stop vocabulary,
unknown → `other`; `prompt`/`completion_tokens` → input/output with `prompt_tokens_details.cached_tokens`
as the cache read; a tool call's `arguments` JSON-decoded, an unparseable one a controlled error).
Same pure-functions-plus-`transport`-seam discipline as the Anthropic client, so it is fully tested
without a network or a key. The **§3.3 real-key guard extends to it**, with the trust source that
the operator-chosen endpoint demands: there is no single host to hard-code (the type exists so the
endpoint can vary), so it is pinned to HTTPS on the canonical `api.openai.com` plus any host named in
the **`BELLWETHER_TRUSTED_MODEL_HOSTS` env var** — trusted config *outside* the evaluated checkout,
which a `base_url` a malicious PR edits into `config.yaml` cannot reach. The cli layer reads the env
var and threads the host set in; the harness never reads the environment itself (spec-notes §9.5).

**The §3.5 sink-path tell then closed.** The `claude-code` hooks write every tool-call event to a
host-owned FIFO (§10.1) the executor mounts into the container, and that mount point was the
constant `/dev/bellwether-events` — an instrumentation tell as reliable as a project-named container:
a skill that checks for it knows it is being evaluated, and the path even carried the project name.
It now joins the other §3.5 identifiers — `SandboxIdentifiers.event_sink_path`, a bare hex leaf under
`/dev` drawn per run from a token *independent of the workspace slug* (so a skill that can read its
workspace path cannot derive the sink), and the executor reads it for both the bind mount and the
hook command so the two never disagree. Randomisation off returns to the greppable
`/dev/bellwether-events` for operator findability, defined once as `sandbox.STABLE_SINK_CONTAINER_PATH`
(the harness's `hook_settings` fallback default now references it, so the fallback cannot drift from
the mounted path). Still under `/dev`, where the bind is proven to work — perfect concealment is not
the goal (§3.5), and active probing still produces the `instrumentation_probe` evidence; the point is
that the cheap fixed-string tell is gone (spec-notes §3.5).

**`doctor` then gained the budget-gate disclosure** — the same silent-no-op audit the tool already
does for `require_scan` and the inert `security_runtime` dispositions, applied to the one remaining
configured-but-inert control. The shipped policy presents `gates.budget.max_cost_usd: 25.00` and
`max_wall_clock_minutes: 60` (and `100.00` on `high`) as if they were dollar/time ceilings, but no
budget gate is assembled into the verdict and neither threshold is read anywhere — a `max_cost_usd`
in policy reads as a spending limit and enforces nothing, exactly the BW-49 trap this project stays
vigilant about. `doctor` now warns that the budget gate does not gate the verdict in this version and
points at the guard that *is* enforced: the per-repetition token ceiling (`bellwether run
--max-tokens` → `RunLimits.max_total_tokens` → a `budget_exceeded` outcome). Advisory, not blocking.
A real dollar/wall-clock budget gate needs pricing infrastructure (per-model cost) and whole-eval
aggregation — a later work package; the disclosure is what keeps the gap honest until then.

**Then a larger batch landed three run-path features together.** First, **the network
assertions evaluate for real** (§12.2, §10.5, §10.6): `no_egress`, `egress_only_to` and
`no_dns_outside` were catalogue entries stubbed to `not_evaluable` via `_plane_gated` even after
the recording proxy and controlled resolver made their planes observed. Each is now an absence
claim gated on its plane being usable for absence (§10.8) — a run without the sidecar still returns
`not_evaluable` with the coverage reason, never `pass` — and, with the plane observed, decides:
only `skill_attributed` flows are the skill's egress (§10.5.0; the model API and declared harness
infrastructure never are), a default-deny **block counts as an egress the skill made** (evidence of
intent, with the block's own action as evidence — the index now records blocked flows with their
host, and `dns_blocked` seqs), and host matching is the proxy's label-boundary rule so a lookalike
cannot pose as a declared host. Second, **the Declared-vs-Observed table gained its `network`
area** (§12.5): a skill-attributed or blocked flow no `network.egress_allow` entry covers is
`exceeded` and so blocks the scope gate; an empty allowlist is the declaration that the skill makes
no network calls, under which every skill flow is `exceeded`; a declared host nothing reached is
`unused` only where the plane could have seen a use, else `not_evaluable`. This closes the "an
undeclared-egress violation is not yet scored" gap without touching the `scope=None` outcome split —
the three now-false "still stubbed" comments were corrected to state the real reason for that split
(an auto-derived absence assertion on an unobserved plane would drag a clean outcome to
`not_evaluable`; the table records that row as `not_evaluable` on its own). Third,
**per-scenario fixtures** (§7.2): `Scenario.fixture`/`defaults.fixture` existed in the model but
were ignored — `_run_fixture` materialised the whole `evals/fixtures/` as every run's workspace.
`cli/fixtures.py` resolves a name per scenario (`evals/fixtures/<name>/`, then the repository's
`.bellwether/fixtures/<name>/`, `empty` for a bare workspace), `plan_matrix` stamps the resolved
path and name on every `RunPlan` (resolved once per scenario, refusing on a missing name *before*
any plan or container), the executor reads `plan.fixture`, and the trace header records
`sandbox.fixture`. One shape is honoured deliberately: every shipped skill uses a flat
`evals/fixtures/` with a `fixture:` label that names no subdirectory, so a name that matches no
directory but sits beside a flat tree resolves to that tree — exactly what the proven live runs
used. A name that resolves nowhere refuses rather than silently running on an empty workspace.
Demo reports unchanged (byte-compare holds), corpus verdicts unchanged (spec-notes §12.5, §7.2).

**A second batch then honoured the rest of the per-scenario fields the model already accepted**
(§7.2, §7.3) — each was parsed and silently ignored. **Multi-turn scenarios run as a preserved
session** on `api-loop`: a `prompt` list used to be joined with newlines into one prompt, a
different test entirely; now the first turn opens the conversation and each later user turn is
appended after the model's reply in the *same* messages, so second-turn drift — the failure mode
§7.3 names — is observable. Only the last turn's reply is the run's `final_output`; every
intermediate reply is on the record through its `model_turn` event, so the trace vocabulary is
untouched. The `claude-code` harness runs one `-p` prompt per session and session continuation
across turns has not been observed in this build, so a turn-list scenario on a `claude-code`
target is **refused by the §16.4 preflight** before any container (gate
`scenario[<id>].prompt`, remedy: an api-loop target), with a last-line-of-defence refusal in the
executor — never flattened. **Per-scenario `timeout_seconds`** (else the suite default) is now
the run's wall clock (`run_limits_for` → `RunLimits.wall_seconds`, the bound that actually stops
both adapters). **Per-scenario `looks`/`n_max`** now reach the sequential design:
`effective_schedule` settles each scenario's schedule while planning — its own, then the suite
default, then the resolved matrix — under the manifest override's consistency rule (looks
strictly increasing, last look equal to `n_max`; an `n_max` that sits on a pre-registered look
truncates the inherited schedule to it, any other refuses rather than inventing a decision point
and silently changing the Pocock correction); `plan_matrix` runs each scenario its own number of
times, `drive_evaluation` aggregates each set under its own schedule and holds it to its own
first-look floor, `SetReading.looks` carries the schedule the set actually ran, and the summary's
"stopped at look k" is counted against it — a stop at N = 4 under a `[2, 4]` override used to be
mis-keyed as the profile's third look. No override reproduces the resolved matrix exactly, so the
default path — and every committed report — is unchanged (spec-notes §7.2/§7.3).

**Then `also_load_skills` was honoured — §7.4 coexistence loading.** The single most under-tested
failure mode the spec names is a skill whose description is broad enough to capture activations
meant for another, and the field that expresses the test (`also_load_skills`) was parsed and
consumed nowhere: every scenario ran with the primary offered alone, so an assertion on *which*
skill activated had no competitor to lose to. `cli/companions.py` resolves each name to a
**sibling** skill directory (`skills/<name>/` beside the skill under test, the one place the §5
layout gives a name meaning), loads it as a full package, and `plan_matrix` stamps the companions
on every `RunPlan` — resolved once per scenario, refusing before any run on a name that resolves
nowhere (a coexistence scenario whose rival is silently absent would report the primary winning
for the wrong reason) or that names the skill under test itself. The executor offers the primary
plus its companions through the api-loop harness exactly as it offers the primary — name,
description, body — so `skill_offered`/`skill_activated` and the existing `other_skill_activated`
assertion work unchanged. Companions are offered, not staged: on `api-loop` the offer is
host-side, so a companion's own scripts are absent in the container and a call into them is an
ordinary recorded error. The `claude-code` harness discovers skills from what is staged, and this
build stages exactly one, so a companion scenario on a `claude-code` target is **refused by the
§16.4 preflight** (`scenario[<id>].also_load_skills`) — plural staging is the same deferred piece
as plugin-layout staging *(since landed: companions are staged for `claude-code`; see the entry
above)*. The full §7.4 machinery (the `bellwether coexistence` command, the
trigger-collision matrix, the library baseline and its delta) is still a work package; what
landed is the loading half every coexistence scenario needs first (spec-notes §7.4).

**`bellwether run --scenario ID` / `--tag TAG` then landed** (§7.2, §20) — the two filters the
spec's CLI surface lists and `tags` exists for ("used for filtering"), neither of which the `run`
command exposed. `select_scenarios` narrows the suite: ids select exactly those scenarios, tags
select every scenario carrying *any* of them, and both together intersect; suite order is
preserved so the plan list and artifact tree stay deterministic. An id the suite does not define,
or a filter that selects nothing, **refuses** naming what exists (the suite's ids and tags) — an
empty selection run to completion would be a clean-looking verdict about no evidence at all, the
same reflex as refusing a suite with no scenarios. Both options are repeatable.

**The rest of the §20 `run` surface followed** — `--targets`, `--n-max`, `--looks`,
`--repetitions`, and `--strict`. `--targets a,b` narrows the resolved target set by alias and
refuses when nothing matches, naming the aliases the config defines. `--n-max` / `--looks` override
the profile's sequential design, and `consistent_schedule` checks the §13.1 invariant once for
every path that builds a schedule (profile, per-scenario override, and CLI flag alike): looks must
be strictly increasing and `n_max` must be the schedule's last look, or the run refuses before
spending. `--repetitions N` is the spec's fixed-N mode: it is exclusive with the sequential flags,
needs at least two runs, collapses the schedule to a single look, and the report is written in
`descriptive_only` mode because no early-stop boundary was applied. `--strict` maps `conditional`
to a non-zero exit through `exit_code_for`, so a pipeline that wants "ready or nothing" gets it
without parsing the report. The per-scenario override path is unchanged; the CLI flag is the outer
layer that per-scenario schedules still sit inside.

**The budget gate is composed (§16.2, §19.1)** — the last configured-but-inert control `doctor`
was disclosing. `gates.budget.max_wall_clock_minutes` and `max_cost_usd` were read nowhere; now
`orchestrate` sums every run's footer (`wall_clock_ms`, `tokens`) across the matrix into a
`BudgetReading` and composes two required gates on it. `budget.wall_clock` is always composed:
over the ceiling blocks; under it with every run footered passes; a footerless run's duration is
*unobserved* and is bounded by the per-run cap the executor enforced (the scenario's
`timeout_seconds`) — passing where observed + unobserved × cap fits, deferring otherwise, never
counted as zero. `budget.cost` prices reported tokens at the new `providers.<name>.pricing.<alias>`
(USD per million tokens, the four §9.3 kinds priced separately) and is composed only when every
target in the matrix is priced; an unpriced matrix gets a verdict note naming the aliases and the
`max_cost_usd` not enforced, `summary.cost.usd: null` (never `0.0`), and a per-profile `doctor`
row — Bellwether ships no prices, so an unpriced target is disclosed, never guessed. `--budget-usd`
(§20) overrides the ceiling for one run. The budget is one matrix-wide gate row (`matrix`), not
one per target. `summary.cost` is filled on every evaluation (tokens, wall clock, footerless
count, unpriced targets; schema `1.1`); the demo artifacts were regenerated and their verdicts are
unchanged (the demo matrix is unpriced and spends 6 min of its 60). spec-notes carries the
reasoning for not composing the cost gate as `not_evaluable`: either reading would demote the
proven live `ready` on a matrix whose spend is fully recorded.

**`bellwether trace` and `bellwether diff` read stored artifacts (§20, §17.1, §17.5).** Both
were `_not_yet` stubs — `trace` claiming "nothing writes traces to an artifact tree yet", false
since WP-12. `cli/trace_view.py` locates a trace by the `run_id` its header carries (the id the
report's evidence links name) under `--out` (optionally one `--eval`), or takes a path, and
renders one line per action — seq, time, plane, kind, and a per-kind summary (the tool and its
input, the outcome and duration, the model turn's stop reason and tokens, the path/host/name)
— with the header's target/coverage and the footer's exit/wall/tokens, or `INCOMPLETE` with the
reason. `--plane`/`--kind` filter and say how many actions were hidden; an ambiguous id (the
same run under two evaluations) is refused naming every candidate. `cli/diff.py` compares two
`summary.json` (an eval id under `--out`, an eval directory, or a file): verdict, each gate by
name (and gates on one side only), the functional and consistency readings, the tier-1
capability profile by set difference (core ∪ peripheral, with peripheral read from its §13.5.2
records — *expansion* is surfaced first as the regression signal), tier-2 sensitive hits, the
security findings, and spend. §17.5's rule holds: the weighted figures are skipped and named
under a different `weights_digest`, tier 3 is always named as not diffed, a schema-version
mismatch is refused, and a different policy or skill is a caveat shown before the table. It
reports and does not apply `gates.regression` (the gate has since landed — below). `report`
was left a stub here (the figures had to be persisted first — also below). Tested against the
committed demo trees.

**Baselines and the regression gate landed (§17.5, §18.4).** `bellwether baseline set|show|clear`
files an evaluation's summary at `.bellwether/baselines/<skill>.baseline.json` under the §17.5
key — skill, payload digest at capture, canon version, target-set digest, platform baseline
version — with `weights_digest` and the policy as metadata beside the key (policy is applied at
comparison time; a threshold tweak must not invalidate every baseline). `run` reads the skill's
baseline and composes a required `regression` gate: tier-1 expansion blocks under
`block_on_capability_expansion` (warns otherwise), a lower-bound drop beyond
`max_pass_rate_drop` blocks (lower bound to lower bound, never point estimates), a new
sensitive-directory hit warns. The comparability table holds component by component: a
different canon version or target set refuses with a verdict note, a different platform
baseline skips the capability sets, a different weights digest skips the BCI. No baseline
leaves the gate uncomposed with a note. `summary.regression` carries the deltas and what was
skipped; the summary now stamps `canon_version`, `platform_baseline_version` and
`matrix.target_slugs` so the key is derivable from any `summary.json` (schema `1.2`). A
`merge=ours` `.gitattributes` is written beside the baselines. The record carries the whole
summary rather than a hand-trimmed subset so the same `diff_summaries` the ad-hoc `diff` uses
is what the gate reads — one comparison, two callers (spec-notes §17.5).

**`bellwether report <EVAL_ID>` re-renders a stored tree.** The figures the renderers take are
now persisted as `metrics/figures.json` (versioned canonical JSON, `report/persist.py`), so the
PR comment and the HTML report are re-rendered byte-for-byte from `summary.json` + the figures;
a tree written before the figures were persisted is refused with the reason. Persisting them
**exposed a §24 determinism bug**: `build_figures` iterated a `frozenset` for the heatmap rows,
so their order followed the process hash seed — the HTML renderer happened to sort, which hid
it, and CI's `PYTHONHASHSEED=0` would never have caught it. The rows are sorted at the source
now, proven identical across three hash seeds. The committed demo trees carry the figures.

**`--depth quick|standard|deep` (§19.1)** presets the matrix options: `quick` is one `small`
target at a fixed 3 (descriptive only — can never be `ready`, and the run output says so),
`standard` is `frontier` + `small` at looks [6, 12], `deep` is every configured target at
[6, 12, 20]. A preset is exclusive with `--targets`/`--n-max`/`--looks`/`--repetitions`, and
every alias it names must be in the matrix — a preset that silently ran on half its targets
would not be the preset.

**`bellwether init-manifest <SKILL> --from EVAL` (§6.2)** infers `evals/manifest.yaml` from an
observed run: the capability profile's tier-3 expansions become `tools.allow`,
`filesystem.read/write`, `network.egress_allow` and `processes.allow`, under an
`INFERRED, NOT REVIEWED` header a reviewer tightens. Finding classes are never laundered into
an allowlist — a canary read, a blocked egress, a DNS lookup, and any path under a §13.5.4
sensitive-directory hit (the exfiltrator's `~/.aws/credentials`) are listed in the header as
observed-but-not-declared. The file is parsed back through the manifest loader before it lands;
an existing manifest is kept unless `--force`, which preserves its reviewed criticality.

**The platform baseline is applied on the run path (§12.6).** `platform-baseline.yaml` was a
shipped document nothing read — `apply_path_baseline` had no callers, so every
harness/toolchain path a run touched counted against the skill's declared scope. `run` now
loads it beside the config and, where it is keyed to the configured sandbox image,
`analyse_run` applies its path entries to each run — the glob-aware, near-miss-flagging
matcher feeding the literal subtraction set — before the capability sets are produced. Absorbed
paths are recorded per run and in `summary.security.runtime.baseline_absorbed` (the audit
trail of "observed − baseline"); a traversal that names an entry but escapes it is never
absorbed and surfaces as `baseline_near_miss`. A baseline not keyed to the image absorbs
nothing and the verdict says why; the applied version is stamped on the run header and the
summary. `doctor` reports absent / present-but-not-applied / applied. Processes and tools stay
unwired: attribution by tree needs the process plane, and the shipped tools list is empty.

**The run cache landed (§19.2).** `execution.cache` was configured and read nowhere. A
`CachingExecutor` now wraps the executor (off by `--no-cache` or config): a plan whose key
matches a live entry under `<out>/.cache/runs` is served from the stored trace, and every
executed complete run is stored. The key is the spec's — payload digest, scenario *content*
(not id), target, fixture digest, harness version, sandbox image, platform baseline version —
plus the model id (the spec: never cache across a changed model id) and the **repetition index**,
which the spec's key omits and this build adds: a set exists to observe variance, and one run
replayed N times would agree with itself by construction. Entries expire by `cache_ttl_days`;
infrastructure failures are never stored. A hit is re-filed under the new evaluation with
`run_id`/`eval_id`/`scenario_id` set for it and the new header field `cached_from` naming the
original observation, so the artifact tree stays consistent and provenance is never lost.
`summary.matrix.runs_cached` counts the replays (schema `1.3`) and the run output says how many
were served from cache. The harness version in the key is the package version for api-loop
(the adapter ships with it) and the configured pin for claude-code (spec-notes §19.2).

**Two review passes then closed twelve gaps before merge**, and they are worth reading as a
group, because every one of them is the project's signature failure mode wearing a different
hat: a number or a plane presented as observed when it was not. The first pass added the
**pinned sampling** and the **companions' payload digests** to the key (both change what a run
is without touching the spec's tuple); made `budget_exceeded` uncacheable; had an **unpinned
claude-code target bypass the cache** rather than key on "unpinned" across a CLI upgrade,
disclosed in the verdict notes; **excluded replayed runs from spend**, so `summary.cost` and the
budget gates cover executed runs only and a cached matrix cannot fail a budget it did not spend;
and had the estimate state its figures as upper bounds with the cache on.

The second pass (`/code-review`, every finding reproduced against the code) closed six more.
The load-bearing one: the key carried the sandbox image but **nothing about what watched the
container from outside**, so wiring the recording proxy for the first time would have replayed
the old networkless traces and left egress `not_evaluable` while the report implied the plane had
been watched. `observability_key` now digests the capture settings, the egress and DNS sidecars
and allowlists, canary planting and the sandbox's resource limits into the key. `timeout`, `oom`
and `pids_limit` join `budget_exceeded` as never-cached, since each is decided by a bound the key
cannot carry. The estimate's **cost ceiling now prices the token cap at each target's dearest
rate**, so the figure the operator approves is the bound the rendered line claims; the expected
figure's divisor excludes replayed runs. The run header records the sampling that was **applied**
rather than requested (`applied_sampling`, asserted against the real request bodies), so an
Anthropic run no longer claims a seed the Messages API never accepts. And a declined estimate
exits **4** rather than the infrastructure code, so a script can tell a choice from a breakage.

**`--deterministic-sampling` (§20, §9.3)** pins temperature 0 (and a seed where the provider
takes one) through a `SamplingSpec` on the api-loop adapter that reaches every model request.
Bellwether still records the provider's defaults unless asked. The run header records the
pinned values and `deterministic_sampling`, the summary marks the matrix, and the verdict
carries a note that the result understates real variance. Refused by the §16.4 preflight on
claude-code targets, where the CLI exposes no such control — never mislabelled as the realistic
condition. Along the way the **PR comment and HTML report now render the verdict's notes** —
the unpriced cost gate, a missing baseline, a platform baseline not applied, pinned sampling —
where the verdict is read, not only in `summary.json`.

**The §19.1 pre-flight estimate is mandatory, with `--yes`.** Before anything is executed,
`run_evaluation` offers the estimate — matrix size, best/expected/worst run counts from the
schedules the sets will actually run (first look / midpoint look / `n_max`), the per-run token
cap, and a cost range where every target is priced: the ceiling prices the token cap, the
expected figure draws tokens per run from the skill's stored baseline where one exists, and an
unpriced matrix gets no dollar figure rather than a guess. The judge/A-B terms are stated as
zero and E[N] as the midpoint (no stopping history exists yet). The CLI prints it to stderr,
asks to proceed on an interactive terminal, and proceeds without asking in CI; `--yes` skips
the prompt, never the estimate. A decline refuses with no container started.

**Companion skills are staged for the `claude-code` harness — §7.4 plural staging.** The
preflight refusal that stood while the build staged exactly one skill is gone: for a
`claude-code` target the executor stages every companion a scenario names beside the skill under
test (`sandbox/staging.py:stage_companions` — the same allowlisted payload, metadata
normalisation and §3.5 machinery check the primary gets, each under its own slug, bound
read-only at the same install root), and the api-loop path is unchanged (companions offered
host-side). The fact the brick rests on — that the CLI discovers *every* directory under
`<config dir>/skills/` and names each in its init record — is observed against the real CLI in
the offline suite (both skills reach `skill_offered`, only the skill under test activates), and
the CI-only executor proof stages a companion through `SandboxRunExecutor` and asserts the same
from the trace. Two skills that slug to one install directory are refused before anything is
copied (they would shadow each other and "which activated" would be undecidable); nothing under
a companion is hashed into the primary's digests, so the run cache and baselines still key on the
skill under test alone. Plugin-layout staging (a bundle installed whole, `--plugin-dir`) stays
open: it needs a CLI fact this build has not observed.

**Per-run limits come from configuration, and the bounds are on the record (§9.2, §12.7).**
`RunLimits` was a set of generic defaults — 32 turns, 128 tool calls, a million tokens — that
every run got no matter what the operator configured, because nothing read a configured value.
`execution.limits` now supplies all three (`run_limits_from_config`), with `--max-tokens` still
overriding the token cap because a flag typed at the terminal should beat a config file. The
wall clock deliberately stays out of it: §7.2 gives it to the scenario, and a second wall clock
in config would silently override the suite author's choice.

The reason this is more than plumbing is what §12.7 does with the outcomes. Hitting the turn or
tool-call ceiling is *timeout*-shaped and **scored as a failure**, while the token cap is
`budget_exceeded` and therefore `not_evaluable`. So a tightened turn limit quietly converts an
operator's choice into the skill's failing score. Three things keep that legible: every run
header now carries a `limits` block with the bounds it ran under (absent, not empty, where a
writer recorded none — the same absent-versus-empty distinction the coverage block turns on),
so a limit-stopped trace says whose ceiling stopped it; `doctor` states the bounds and what
hitting each one produces before a forty-minute run rather than after; and the limits join the
run cache's observability key, because a run stopped at a ceiling is a different observation
from one that ran to its own end, so raising a ceiling must miss rather than replay the
truncated trace. The tests run the real adapter into each ceiling rather than asserting the
plumbing, and each was proven to fail with its wiring reverted.

**Three bricks: the interception probe, CodeQL, and whole-bundle plugin staging.**

**WP-14's live half (§9.2, §20).** Doctor reported the recording proxy as *configured* and stopped
there, which is a different claim from the sandbox *trusting* it — and the gap between them is the
tool's most dangerous state, because a container that rejects the CA makes no observable egress and
the run's trace reads as a skill that never touched the network. `--probe-interception` now
executes: the real sidecar, a client container on the run's own internal bridge carrying the §9.2
trust environment, a genuine HTTPS request, and the proxy's own flow log as the answer. The design
turn worth recording is that the proxy records a flow **on receipt**, before forwarding, so a
recorded probe host establishes that the client completed the handshake against the proxy's
certificate even when the upstream does not exist. The probe therefore needs no peer server and no
reachable destination: it uses an unresolvable `.invalid` name, and nothing leaves the machine.
Three outcomes are kept apart — confirmed, a rejected CA (`critical`, and doctor exits non-zero),
and *inconclusive*, which says so rather than passing, because "we could not tell" and "the CA is
not trusted" call for different actions. The container proof asserts the counter-case too: with the
CA stripped from the trust environment the same request is refused and no flow is recorded, so the
probe is one that can fail.

**CodeQL.** `security-and-quality` over the Python package, on pull requests, `main`, and weekly so
a newly published query reaches code already written. Actions SHA-pinned like everything else. A
tool that renders security verdicts on other people's code while running no static analysis of its
own is asking for a trust it does not extend to itself.

**Plugin-layout staging (§5/§6/§18).** An Agent Plugin is now installed **whole** — staged with its
manifest and everything outside a skill's own directory, mounted, and loaded with `--plugin-dir` —
rather than each skill lifted out of it. Bare-directory staging meant a skill whose body points at a
sibling path worked in a real client and failed under evaluation for a reason that was about
Bellwether. §3.5 applies bundle-wide: no `evals/` anywhere under the bundle is copied, each one is
named rather than silently dropped, and the outcome is asserted rather than trusted.

A `/code-review` pass over the branch then found seven more, all fixed with a test each and each
proven to fail with its fix reverted. The two that matter most were both "the check does not check
what it says": the probe ran its client from the **sidecar** image while rendering a row about the
sandbox trusting the CA — the one container the claim is about, and the one case it could not fail
for — and whole-bundle staging left the bare payload mounted *as well*, so the harness held two
copies of the skill under test and which activated was undecidable. The rest: version-control
metadata is excluded from a staged bundle (`.git` carries the evaluation machinery even after the
working tree's `evals/` is left behind), non-regular files are skipped rather than read (a FIFO
would block the copy forever — reverting that fix hung the test run, which is its own proof), the
install path is resolved before it is trusted (a lexical containment check does not catch `..`),
the bundle digest keys the run cache, and a probe that cannot run is a doctor row rather than a
traceback.

The part of that brick worth reading is what the CLI told us. Rather than assume how a bundle is
loaded, the real CLI 2.1.274 was run with `--plugin-dir` and its init record read: every skill under
`skills/` is offered, and **each is reported qualified by its bundle** (`demo-bundle:demo-skill`).
Bellwether's activation assertion compared names exactly, so whole-bundle staging would have scored
the skill under test as never activating on every plugin run — a false negative produced entirely by
how Bellwether staged the skill, which is the worst kind because it looks like evidence about the
skill. `skill_name_matches` strips the bundle qualifier from the recorded side only, so a scenario
can still name one bundle's skill exactly; the trace keeps what the harness actually said. A test
pins the qualification against the real binary, so a future CLI that drops it fails there rather
than leaving the matcher quietly over-matching.

A **second review round** over the same branch found five more of the same shape — a path that
renders a clean result without observing the thing it names — and each is fixed with a test
(spec-notes §3.5/§9.2/§19.2/§24). The sharpest: the probe client was hard-coded to `python3`, and
running the shipped `claude-code` sandbox base settled what it carries — `node` and `sh`, no
`python3`, no `curl`, no `openssl`. The probe corrected to use the sandbox image could therefore
only ever report *inconclusive* on the one image that matters, while its CI proof passed by
substituting the sidecar. The client is now a `sh` dispatcher preferring Node, which is the point
rather than a fallback: Node ignores the system trust store and reads `NODE_EXTRA_CA_CERTS`, the
mechanism §9.2 calls not optional. It is run for real against an intercepting socket server
offline, in both the trusted and the rejected case, and the container proof runs on the sandbox's
own digest-pinned base as well as the sidecar. The rest: a §7.4 companion that is a sibling in the
installed bundle is no longer staged a second time (two copies of the competitor, in exactly the
scenarios companions exist to decide); the bundle's §3.5 exclusion and its leak assertion now fold
case and Unicode form as the payload's always did; `plugin_digest` digests what staging copies
rather than the whole checkout, so a plugin developed in place stops thrashing the run cache; and
the bundle installs under `PluginBundle.name` rather than the host checkout's directory name, so
the container path is the same on every machine (§24).

A **third round** found seven more, and one of them was the §3.5 hole the first two walked past:
`evals/` is the *skill's* machinery, but a plugin bundle that is its own checkout also carries the
**repository's** — `.bellwether/` (config, platform baseline, stored baselines, and the *policy*:
the gates the skill is about to be judged against) and `.bellwether-out/` (the traces of previous
evaluations). Staging the bundle whole put both in the container, which tells the skill not merely
that it is watched but exactly what would clear it. Both are excluded now, by name taken from
`config.document.CONFIG_DIR` so a rename cannot leave the exclusion behind. The rest, in rough
order of cost: a refusal raised after the proxy/resolver standup used to leak both sidecars and
their bridges (a refusal that costs a manual `docker network rm` is a refusal that discourages
refusing); deriving the install path from `PluginBundle.name` alone broke `bellwether run .` on a
bundle with no declared name, so the resolved directory name is the fallback again and the guard
also rejects `:`, which is legal in a directory name and fatal in a bind mount; the digest hashed
escaping symlinks the copy refuses; and on the probe, `probe_host` reached the interpreter but not
the command, and the client container had neither a name nor a deadline, so a timeout left it
attached to the bridge it was supposed never to leak.

A **fourth round** found three more, all inside round three's own code. The exclusion list added to
close the §3.5 hole named `.bellwether-out/` — taken from the documentation — while the name `--out`
actually defaults to is `bellwether-runs`: the fix for a check that did not check what it said
contained one. Both names now come from `config.document`, the repeated `--out` literal is gone, and
a test asserts every command sharing that default shares the object. The teardown guard started one
statement too late (the resolver's own standup sat above it, the one case where a proxy is up and
nothing else would close it) and ran its closes in sequence, so the first to raise skipped the rest;
both were proven by reverting them. Two further findings are left for their own brick because they
are in files this change does not touch — see the list below.

**One declared control now actually gates, and §12.6's last applicable area is applied.** The
shipped policy lists thirteen `security_runtime` dispositions; four drove the verdict, and the
other nine read to anyone opening the file as controls that are on. Two of them had their evidence
already computed, aggregated and *rendered* — apparently one gate each away from working. Only one
of the two turned out to be: the second is withdrawn below, which leaves **five** enforced and
**eight** inert.
**`sensitive_directory_access` (§13.5.4)** is scored: a skill could read `~/.aws/` on every run and,
so long as it exfiltrated nothing, clear every scored gate in the profile. Presence before
coverage, because §13.5.4 is frequency-independent by design; only the *pass* waits on Plane A
supporting an absence claim. The gate reads *undeclared* hits — `legit-credential-reader` declares
its credential read and must stay `ready`, and a declaration excuses a hit only by naming a
location under the sensitive directory itself, since a blanket `${HOME}/**` is exactly what
§13.5.4 exists to see through. The matching rule took three attempts and the first two were
bypassable: matching the sensitive token as a *segment anywhere* ignored which root the
declaration sat under, so a decoy `${WORKSPACE}/fixtures/.ssh/known_hosts` in a skill's own
repository excused a real read of `${HOME}/.ssh/`; declaring one sensitive directory excused the
home root; and a declared *write* excused an undeclared *read*. The rule is now anchored,
zone-aware and direction-aware, and each bypass is a test that fails against the old rule.
A **second** review then found the anchored rule had introduced the exact defect it was meant to
prevent: `workspace_delete` fell through the direction split, so no manifest entry of any kind
could excuse a deletion under a sensitive directory, and a skill running `git status` — which
removes `.git/index.lock` — sat at `not_ready` with no escape. The classification is now shared
with `_BASELINE_WRITE_CLASSES` and total. The same review found the gate's own advice named an
entry the gate rejects (`${HOME}`, for a home-root hit), that `${HOME}/.` and `${HOME}/..` excused
the home root, that brace-expanded declarations were honoured by the scope gate and refused here,
and that the configured-list fix was untested at both of the hops that had actually been
missing. A **third** round then measured the claim *"every fix revert-proved"* and found it false
for three of eleven — including a config-validator branch that was unreachable dead code, so the
defect it claimed to fix was still there. Each now has a test that fails without it; the
correction is recorded in spec-notes rather than quietly applied. The same round found that making
the direction split *total* had opened a bypass one zone over (a `filesystem.read` entry excusing
`egress:evil.com`, since the token extractor does not ask which zone produced a hit), that brace
expansion re-created the undeclarable-hit class for brace-named locations and was uncapped against
an attacker-controlled manifest, that a `..` declaration bought a blanket pass on the directory it
walked out of, and a §24 violation whose text reaches the byte-compared report. A **fourth** round
found that the `..` fix had opened a worse hole than it closed — `_traverses` ran on the raw entry,
so `${HOME}/{..}` walked past it and `${HOME}/.ssh/{..}/public/**` restored the blanket pass the
literal check had just removed — that the brace cap bounded nothing but binary groups and sat on
the wrong door (`glob_to_regex`, which reads the manifest under review, still took 78 seconds on a
111-character entry), and that "every fix revert-proved" was false for the second commit running.
The per-change measurement is now published as a table rather than asserted as a sentence.

**The matcher was then rewritten to normalise rather than enumerate**, because three of the four
rounds' headline findings were regressions from the previous round's fix, all in the same
predicate — the signature of a blacklist, where every reject-clause has an unenumerated spelling
(`..` refused, `{..}` through). An entry is now reduced to the path it certainly reaches — braces
expanded, everything from the first wildcard dropped, `.` and `..` resolved — and compared
segment-wise. The old clauses become consequences. The 48 tests encoding every bypass and false
positive found across the four rounds were held unchanged as the contract, and one of them caught
a defect in the first attempt. The new rule also fixes three false positives and five traversal
spellings **no round found**. **`harness_state_write` (§3.5/§10.2) was attempted and withdrawn**: the gate
was built and then removed before it shipped, because it could never fire — §10.2 attributes such
a write by a Plane A anchor, and Plane B actions carry no `Correlation` at all, so the condition is
false for every write that exists. That also surfaces a pre-existing gap worth its own brick: the
§10.2 rule excludes *every* harness-state write from the capability set, not just the harness's own
churn, and correlating overlay writes back to their tool calls is §11.5 step 3. And **§12.6's
`tools`** are applied rather than merely parsed, matched by exact
name (a glob there would let one `*` absorb the whole tool surface), through a new tier-1
absorption channel since a tool is identified by its class and not by its target. `processes`
still waits on the §10.3 process plane. Doctor's inert list is one shorter — eight, not seven:
`harness_state_write` is still configured and still inert, and the withdrawal is exactly why it
must keep being named. The `tools` half also had the inert-allowlist trap it exists to close:
`observed` was composed as `tool:<name>` for every call regardless of the tool's real tier-1, so
a baseline naming `read` — classed `workspace_read`, never `tool:read` — matched the invention,
absorbed nothing and said nothing. It now raises a near-miss, as the path half always has.

**The configured sensitive-directory list reaches the analysis.** `canonicalize` has always taken
a `sensitive_directories` parameter its docstring calls "configurable, defaulted centrally", and
`config.yaml` has always shipped a `metrics.sensitive_directories` list the template invites users
to extend. No caller joined them, so every run fell back to the constant and a user who added a
directory got nothing. Harmless while the hits were only rendered; not harmless once they gate.
The two lists had also drifted where it mattered most — the config said `~/`, the matcher yields
`~` — so connecting them without reconciling them would have switched the home root off silently.
The default now derives from the constant, and a config entry the matcher could never produce is
refused at load rather than read as protection.

**The platform baseline is published, because it is an allowlist (§12.6).** §12.6 requires its
full contents in the report, collapsed, and says why in one line — *a hidden allowlist in a
security tool is a liability*. That was unimplemented: the report carried a version string and
nothing else, while scope evaluation ran against `observed − platform_baseline`, so every entry
was something the skill did that declared-vs-observed does not show. Worse, two things were
computed and then dropped on the floor — `baseline_absorbed` (whose own docstring calls it "the
audit trail") and `baseline_near_misses`, which §12.6 says MUST raise a finding rather than be
silently absorbed. The code refused to absorb them and then discarded the finding, which lands
where absorbing them quietly does. `Summary.platform_baseline` now carries the contents, what was
absorbed, and the near-misses; the HTML report renders it collapsed and the PR comment carries it
too, with near-misses **outside** the collapsed block in both. `applied` is kept distinct from an
empty `absorbed`, and no configured baseline yields no block, because absent is not empty.
`SCHEMA_VERSION` → `1.4`. Found en route: `bellwether version` printed `summary.json schema 1.0`
from a second constant while every summary it wrote stamped `1.3` — the duplicate is gone and a
test asserts the two agree. Still not *applied*: `tools` and `processes` are published but
`baseline_absorption` handles paths only (tool attribution next; process attribution waits on the
v0.3 process plane).

**The harness's egress is no longer the skill's capability, and a companion is a name again.**
Two loose ends carried out of the previous brick; the second was much the larger. §13.5.1 weights
`egress:<host>` at 10 and says "(non-model)" in the same breath, and the canonicalizer did not
honour the parenthesis — every egress class collapsed to the same capability, though the assertions
layer already filtered to `skill_attributed` everywhere. Under `claude-code`, where the CLI's model
calls leave through the same proxy a skill's would, a skill that made **no request at all** came
out holding two weight-10 capabilities: the model API and the harness's telemetry host. They fed
the BCI, `max_rare_capability_risk` (whose cutoff is a risk weight, so a telemetry host in one run
of six could block a verdict), the §17.5 baseline, and `init-manifest` — which wrote
`api.anthropic.com` into the *skill's* `network.egress_allow`, so a later genuine exfiltration to
the model API would read as declared-and-allowed. It also made the two harnesses incomparable,
since api-loop runs the model host-side and never crosses this proxy. Non-skill egress is now
`egress_infrastructure:<host>` at the floor weight, reclassified rather than dropped (it stays in
the step sequence), with an unlabelled flow deliberately reading as the *skill's*. `CANON_VERSION`
→ `1.1`; the committed demo artifacts and golden trace were regenerated, and every demo verdict is
unchanged. Separately, `also_load_skills` entries are validated as a single path component before
they are joined: `../…` reached outside the skills tree, and `./<name>` walked past the
self-companion refusal to put the skill under test in front of the harness twice.

A **fifth round** found nothing merge-blocking and four worth fixing, three of them in the previous
two rounds' own code. The `--out` exclusion was keyed on the *default* directory, so `--out
artifacts` on a self-checkout bundle still staged previous evaluations' verdicts: `staged_exclusion`
and `plugin_bundle_digest` take `exclude_roots` now and the caller passes the artifact root it is
actually writing to — the whole root, since the evaluations *beside* this one hold the traces. The
run's own `finally` still tore down sequentially four lines below the region that had just been
fixed, so a raising `stop_persistent` leaked both sidecars on the path where the run *succeeded*;
both go through `_tear_down` now, which attempts every step and attaches what failed as a note to
the propagating exception rather than discarding it or replacing the run's own error. And the drift
guard written last round skipped any command that had already drifted, so it names the seven
commands exhaustively instead of counting them.

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
| Live model client (`harness/live_client`) — Anthropic Messages API + OpenAI Chat Completions behind the `ModelClient` seam | **done** — both `anthropic` and `openai_compatible` implemented |
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
| **WP-17 `claude-code` adapter** — the real CLI runs headless *inside* the sandbox (`harness/claude_code.py`): its stream-json output is Plane A, its `PreToolUse`/`PostToolUse` hooks write to the host-owned sink FIFO and are cross-checked against stdout (`trace_inconsistency` on disagreement), its model calls leave only through the proxy carrying the sandbox-scoped token, telemetry is disabled and its hosts declared infrastructure; `Read`/`Write`/`Edit`/… map onto the same capabilities as api-loop's tools through one vocabulary table; trigger metrics are portable | **done** — proven offline against a real headless session of CLI 2.1.257 (golden fixture + a live local run where the binary is present); the in-container proof is the CI-only `test_execution_claude_code_docker.py` |

1430 tests: 1372 offline, 58 under the `docker` mark (47 run locally, 11 CI-only skips with stated reasons; all 58 run on CI, zero skips). All green. These three numbers are asserted against a real collection in `tests/test_docs_accuracy.py` — this line drifted inside the very change that added a test against drifting prose numbers, which is argument enough.

## What's next — remaining work, in recommended order

Phase A and the recording-proxy spine of Phase B are done, and the live loop reaches `ready`. The
coverage-honesty (WP-18) and calibration (WP-19) proofs are in, and the v0.1 acceptance corpus
(WP-20) is complete. What remains for v0.1 is **one package: the second harness** (WP-17). The
order below reflects dependencies and reuses momentum — it is not the raw WP numbering,
because the build deliberately inserted the executor-integration + live-proof work (unnumbered) that
made WP-13 usable end to end. `docs/BUILDPLAN.md` carries the same note.

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
   key and open build egress live. The five defects above were each isolated by reproduction on the
   real Docker daemon and the real CLI binary in this session, without a paid run.*
4. **Corpus & acceptance (WP-20) — done.** All eleven v0.1 skills are in and CI-asserted: the
   security slice (`canary-thief`, `dns-thief`, `legit-credential-reader`), the functional slice
   (`benign-stable`, `file-selective`, `always-fails`), and the frequency-independence/scope/shape
   slice (`rare-canary-reader`, `scope-creeper`, `over-declared`, `slow`, `benign-chaotic`). The
   §24 rows that remain (`over-triggering`, `git-peeker`, `telemetry-noisy`, the chunked thieves,
   `prompt-channel-thief`, `server-tool-user`, `fetch-and-exec`, `obfuscated-injection`,
   `eval-aware`, `model-divergent`, `oom-hog`) each need a post-v0.1 subsystem — the static
   scanner, the probe suite, or a real-network corpus run — and land with it. With WP-17 in,
   **every v0.1 work package is built**; what is left for the v0.1 line is the live proof of the
   second harness and the loose ends below.

Loose ends to fold in along the way: **applying the platform baseline's `tools` and `processes`**
(the path half absorbs; the whole baseline is now *published* in the report, but `tools` and
`processes` are not yet matched against — tool attribution needs no new plane and is the next
increment, §10.3 process trees wait on the v0.3 process plane). *(WP-14's live doctor
interception probe, plugin-layout staging, the `also_load_skills` path-traversal fix and the
harness-egress capability split have since landed — see the entries at the top.)*
(`openai_compatible` provider support and the per-run §3.5 **sink path** have since landed — see the
entries at the top.)

**The live smoke run is armed to observe egress.** `examples/live/config.yaml` now sets
`egress.image`, and the `Bellwether` workflow builds that sidecar image before the paid run — so a
labeled live PR stands the dual-homed proxy up around each repetition and egress reads *observed*.
A benign skill is observed-clean, which lifts the `conditional` cap the unobserved plane imposed:
this is the run that reaches **`ready`**. The smoke policy keeps `egress_outside_allowlist` at
`warn` for this first proof (a clean run passes either way; a surprise flow in the shakeout warns
rather than reddening the run before the pipeline is trusted); promoting it to `block` is the
deliberate follow-up. A test guards the config against rotting back to proxy-off.

**The producer path has an executor-level done-when on CI.** `test_execution_proxy_docker` stands
a real mitmproxy sidecar up around a real sandbox run *through `SandboxRunExecutor`* — the two
bridges, the dual-home attach, the CA written to the shared volume and mounted into the sandbox, the
run routed through the proxy — and asserts egress reads **observed** (not unavailable), the benign
skill's trace is observed-*clean*, and no bridge leaks on teardown. It exercises the load-bearing
unknown: if mitmproxy does not write its CA where the executor expects, `ca_cert_path()` raises and
the run fails loudly rather than producing a zero-egress trace (§9.2). This is the same observed-clean
state that lets a benign live run reach `ready`; the remaining step is proving it against a live model
on a labeled PR.

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
The declared scope was, at this point, still intentionally not applied — its auto-derived egress/DNS
assertions wanted the DNS plane observed too. (Since closed: declared scope applies on the live path
as the Declared-vs-Observed table, and the `no_egress` / `egress_only_to` / `no_dns_outside`
assertions now evaluate for real against the observed planes — see the entries at the top.)

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
  is visible (§9.3). `build_model_client` dispatches on provider type; both `anthropic` and
  `openai_compatible` are now implemented (the latter translates the loop's Anthropic-shaped messages
  into the Chat Completions array and back — see the entry at the top and spec-notes §9.5).

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

1. **Residual run-path gaps (now that the live run itself is proven).** Most of this item has since
   closed: declared scope applies on the live path as the Declared-vs-Observed table (BW-47), the
   network area of that table is scored (an undeclared egress host blocks the scope gate), the
   `no_egress` / `egress_only_to` / `no_dns_outside` assertions evaluate for real, **per-scenario
   fixtures** are expressible (`fixture: <name>` resolves per scenario and rides on each `RunPlan`),
   and the precondition check, weight validation, §21 refusal and FIFO sink are wired into
   `doctor`/`run`. **Closed since:** the per-run limits are configuration-derived rather than
   the generic defaults (`execution.limits` → `run_limits_from_config`), recorded on every run
   header, and in the run-cache observability key.
2. **WP-15's controlled DNS resolver — the container half.** The host core (allowlist, NXDOMAIN
   decision, query record, canary-in-labels scan) is done and offline-tested. What remains is its own
   sidecar (a second peer on the internal bridge, `dnslib`/`coredns`), the §3.3 invariant-3 UDP/53
   lockdown that forces every lookup through it, and the `dns_query`/`dns_blocked` trace actions —
   the CI-only container slice, mirroring the proxy sidecar.
3. **The `openai_compatible` live client — done.** The Chat Completions message-shape translation
   the Anthropic client did not need is implemented (`OpenAiCompatibleClient`), with the §3.3 key
   guard extended to it via an out-of-checkout trusted-host env var. See the entry at the top.

**WP-14's live half is closed.** `bellwether doctor --probe-interception` stands the recording
proxy up, runs a client container on the sandbox's own internal bridge with the §9.2 trust
environment, issues a real HTTPS request and reads the proxy's flows. The interception test above
deliberately used plain HTTP, which covers injection and blocking but says nothing about whether
the sandbox would accept the proxy's certificate — and a sandbox that would not produces
zero-egress traces that read as a clean skill.

## Outstanding actions

### Code

| Item | Where | Why it is still open |
|---|---|---|
| `fixture.yaml` generated content | §9.1 step 1 | A half-designed generator is worse than none. Needs a schema decision. |
| `requires.min_bellwether_version` in the §16.4 preflight — **closed** | `cli/preflight.py`, `verdict/precondition.py` | The last disclosed BW-51 skip. Now checked: `preflight_failures` threads the running `__version__` into `check_preconditions`, which owns a committed conservative-PEP-440 ordering rule (`_parse_version`/`_version_lt` — no `packaging` dependency). A running version below the policy minimum, or an unparseable minimum, refuses before spending; the shipped `high` profile (min `0.3`) now refuses on both the version and its missing planes on a v0.1 runner (spec-notes §16.4). |
| Weight validation wired to `doctor`/`run` — **closed** | `cli/run.py`, `cli/app.py` | Both validators are now called on the real paths. `run_evaluation` runs the cross-document §16.1 check (policy `capability_risk_weights` × the manifest's `tools.deny`, mapped to `tool:<name>`) and refuses before spending if a manifest-denied class is weighted 0 — that would erase it from the risk-weighted Jaccard and let a skill post a clean consistency score while using a denied tool. `doctor` runs the §13.7 BCI-weight check on `config.metrics.bci_weights`, surfacing a zero component (which silently drops from the composite — the config model already rejects a non-1.0 sum) named to file and key, as a `warn` row (advisory, not blocking). |
| Sink container path drawn per run — **closed** | `sandbox/identifiers.py`, `cli/execution.py` | §3.5: the fixed `/dev/bellwether-events` FIFO path was an instrumentation tell a skill could grep for. It is now `SandboxIdentifiers.event_sink_path`, a bare hex leaf under `/dev` drawn per run from a token independent of the workspace slug; the executor reads it for both the bind and the hook command. Randomisation off returns to the greppable stable path (`STABLE_SINK_CONTAINER_PATH`, the single source the harness fallback also references) for operator findability (spec-notes §3.5). |
| The claude-code adapter's live-model proof — **landed** | `.github/workflows/bellwether-claude-code.yml`, `examples/live/config-claude-code.yaml` | The first labelled `claude-code` live run happened on PR #65 and reached **`ready`** — 8 gates pass, functional 6/6, DNS clean — exercising a real model, the live dual-sidecar topology, and a cloud runner's networking. It found five environment defects the CI-only scripted proof could not plus one dual-harness tool-name-casing fix (spec-notes §9.4/§10.6), all resolved. The claude-code harness is now proven live end to end. |
| Live model client — `openai_compatible` variant — **closed** | `harness/live_client.py`, `cli/run.py` | `OpenAiCompatibleClient` translates the loop's Anthropic content-block messages into the Chat Completions array (system → leading `system` message, `tool_use` → assistant `tool_calls` with JSON-string arguments, `tool_result` → per-id `tool` messages) and the response back. The §3.3 real-key guard extends to it: pinned to HTTPS on `api.openai.com` plus hosts named in `BELLWETHER_TRUSTED_MODEL_HOSTS` (out-of-checkout config the cli threads in), so a tampered `config.yaml` base_url cannot redirect the key (spec-notes §9.5). |
| Budget gate — **closed** | `cli/orchestrator.py` (`budget_reading`, `_budget_wall_clock_result`, `_budget_cost_result`), `config/models/provider.py` (`ModelPricing`) | `budget.wall_clock` is composed from every run's footer with a footerless run bounded by the per-run cap or deferred; `budget.cost` prices reported tokens at `providers.<name>.pricing` and is composed only for a fully priced matrix — an unpriced one is disclosed in the verdict notes, `summary.cost` and `doctor`, never guessed. `--budget-usd` overrides the ceiling (spec-notes §16.2/§19.1). |
| `pids_limit` exit reason never produced | `sandbox/docker.py` | Docker gives no distinct exit code; needs another signal to distinguish it from `harness_error`. |
| Held-out probe set (§7.6, §3.5) | — | Must not appear in `--help`, the README, or the public corpus when it lands. |

### Repository settings — human-only

| Item | Status |
|---|---|
| Branch protection on `main` requiring `check` and `container` | **reported done; not verifiable from here** — the branches API still shows `main` as `protected: false`. That is consistent with a *ruleset* rather than classic branch protection, which the flag does not reflect. Worth confirming, because it is the control that closes the stale-check hazard below. |
| Private vulnerability reporting enabled | open — `SECURITY.md` already points people at it |
| Dependabot | **config committed** (`.github/dependabot.yml`, github-actions + uv, weekly) — enable it in repo settings if it is not on by default |
| CodeQL | **workflow committed** (`.github/workflows/codeql.yml`, `security-and-quality` over the Python package, on PRs, `main` and weekly, SHA-pinned) — nothing to enable for a public repo; confirm results appear under Security → Code scanning |

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
