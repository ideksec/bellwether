# Bellwether

A CI/CD harness for AI agent skills — run them, watch what they actually do, and decide
whether to ship them.

Bellwether executes a candidate skill many times, across multiple models, inside an
instrumented sandbox; captures a deterministic record of everything the agent actually
*did*; measures how much that behaviour varies between runs; and renders a release
verdict against a policy the repository owner controls. The matrix is designed for
multiple providers; the current live client supports Anthropic, so a multi-model
evaluation today means several Anthropic models.

**The name is the thesis.** A bellwether is the lead sheep whose bell signals that the
flock is about to move. It warns; it does not vouch.

## Where this came from

This started as an argument at Black Hat. A few of us were debating (arguing) about the idea of enforcing
shared, installable agent skills — a plugin repository, basically — and the obvious tension
that comes with it: the same thing that makes a skill marketplace useful (grab someone
else's skill, drop it in, done) is exactly what makes it dangerous (you just handed an
untrusted set of instructions to a model with tools). Reviewing the prose of a `SKILL.md`
tells you what it *asks* for, not what the agent *does* once a real model reads it. The
debate was less "is this a problem" and more "could you actually build a gate that catches
it before it ships." Bellwether is the attempt to find out.

So treat this as **an experiment, not a product.** It's early, opinionated, and moving fast;
interfaces will change and things will break. It's also worth saying plainly: **most of this
codebase was written with heavy agentic assistance** (Claude Code doing the building, with a
human driving direction, review, and the hard calls). That's part of the experiment too —
both the tool and how it got made. The design decisions, the threat model, and the "don't
oversell it" discipline are deliberate; see [docs/spec-notes.md](docs/spec-notes.md) for the
reasoning behind the divergences.

## Status

**Pre-v0.1. Under construction — but the loop closes end to end.** On a real pull request, a
changed skill is detected, run six times in a hardened sandbox behind a recording proxy that
observes its egress, scored across the gates, and posted back as a verdict — and a benign skill
has reached **`ready`** this way, on CI, against a live model, with every run's evidence uploaded
as a downloadable artifact. That is the whole thesis walking on its own legs.

Under it, the entire offline analysis path is built and tested — the skill parser, the trace
format, the sandbox, the capture planes, the `api-loop` harness, canonicalization, the platform
baseline, the assertion engine, the metrics, the verdict engine, and the report layer. The
**recording proxy is wired into the live run**: credential isolation (the real key reaches the
provider but never the container), a default-deny egress allowlist, and a dual-homed sidecar on
an internal bridge that is the sandbox's only route out — so egress is *observed*, not assumed.
**Canaries are planted and scanned in live runs, and a leak gates the verdict.** The controlled
DNS resolver runs as a second sidecar with its queries recorded as Plane E. The **live model
client** (Anthropic), the `bellwether run` CLI, and the shipped GitHub Action round out the
pipeline.

What remains is **breadth, not a missing spine**: turning the captured-but-unscored
credential-read plane into a gate, the static scanner, process/read capture, the `claude-code`
harness adapter, and the rest of the v0.1 acceptance corpus (its security slice is in). See
[docs/STATUS.md](docs/STATUS.md) → **"What's next"** for the ordered plan, and the table below
for exactly what is implemented versus refused-with-exit-3.

### See it

There's now something to look at. `bellwether demo` renders three example skills to three
reports — including a self-contained **HTML report** — entirely offline, through the same
analysis pipeline a live run uses (a scripted transcript stands in for the model and the
container, nothing below it is faked):

```bash
uv run bellwether demo          # writes examples/reports/<eval>/report/report.html
```

The three are chosen to reach three different verdicts, so the report's shape is visible in
each: a clean note-taker (`conditional`), a **credential exfiltrator that passes its task but
reads `~/.aws/credentials`** and is caught by the declared-vs-observed check (`not_ready`),
and a flaky formatter whose pass rate falls below the gate (`not_ready`). The rendered
reports are committed under [`examples/reports/`](examples/reports/); the example skills
themselves are under [`examples/skills/`](examples/skills/).

**[docs/STATUS.md](docs/STATUS.md) is the current state of the build** — what is done,
what is next, what is outstanding, and what a new contributor needs to know about the
environment. [docs/BUILDPLAN.md](docs/BUILDPLAN.md) has the ordering.

New here? [pitch.md](pitch.md) is the short version of what this is and why.

### What the live verdict gates today

Being explicit about this matters more than looking finished. On the live `run` path, the verdict is
composed from eight gates, and these are the checks that can actually move a skill off `ready`:

- **evidence** — enough of the repetitions produced evaluable traces;
- **functional** — the pass-rate *lower bound* (not the point estimate) clears the policy threshold;
- **consistency** — the behaviour is stable across runs (Wilson/BCI, risk-weighted capability
  Jaccard, modal-trajectory share, mean edit distance, and a rare-high-risk-capability check);
- **scope** — declared-vs-observed: a skill that calls a tool, or reads a path, outside its
  `manifest.yaml` is flagged and blocked. *This now runs on the live path, not only in the demo* —
  earlier builds deferred it and rendered a false "within scope" for every run;
- **security_runtime.egress** — egress to a host outside the default-deny allowlist, from what the
  recording proxy observed;
- **security_runtime.canaries** — a planted canary appearing at any non-model destination (final
  output, a DNS query name, tool arguments, an egress request, a written file) blocks under the
  default policy. Where canaries were not planted, the gate defers as `not_evaluable` — an
  unwatched channel is never called clean;
- **security_runtime.dns** — a lookup of a name outside the allowlist, from what the controlled
  resolver logged (Plane E). An HTTP proxy never sees UDP/53, so this is the gate on the covert
  channel that routes around the egress plane. Where the resolver was not wired, the gate defers
  as `not_evaluable`, same rule as the other two;
- **security_runtime.canary_reads** — a planted canary appearing in the model's context with no
  recorded read carrying it there (`canary_without_read`, §10.4.1). Every composed model request
  is scanned host-side; a marker that entered through a tool result grades `canary_in_context`
  (info — read-then-send is the legitimate shape), and the gate fires only on the value arriving
  by a path the trace cannot account for. This observes the residual channel the threat model
  names — the allowlisted model API — which cannot be blocked without breaking the evaluation.

What is **captured as evidence but does not yet gate** the scored verdict: undeclared
credential reads (`credential_read_undeclared` — needs the read-capture plane), sensitive-directory
access, and the volume/anomaly checks. Their findings appear in the report, but a `block` disposition
on them will not, on its own, make a verdict `not_ready` in this version — wiring each into a gate is
per-plane roadmap work. `bellwether doctor` names exactly which configured dispositions are inert, so
a control is never mistaken for an active one. The model-API channel is by design out of the egress *scan* — it legitimately carries the skill's
content to the provider — which is exactly why it gets its own read-state gate above
(§ THREAT_MODEL).

## What it is for

An agent skill is a directory containing a `SKILL.md` and optional supporting files. It
is distributed like code, reviewed like prose, and executes like neither — the effect of
the instructions depends on which model reads them, what else is in context, and
sampling.

Reading a skill tells you what it *asks* the agent to do. It does not tell you what the
agent *does*. Bellwether's claim is that the useful unit of evidence is a **trace**: a
deterministic, machine-readable record of the tool calls, file operations, network
egress, process executions, and credential accesses that occurred while an agent
operated under that skill's influence. Traces can be asserted against, diffed, and
aggregated across repetitions into a variance measurement. Prose cannot.

Four properties follow:

1. **Repetition is mandatory.** A single run of a nondeterministic system is an anecdote.
2. **Multi-model is mandatory.** A skill that works on a frontier model and fails on a
   small one is working on one configuration, not working.
3. **Observation beats declaration.** A claim that cannot be evaluated is reported as
   `not_evaluable`, never silently passed.
4. **No observer inside the observed.** Every capture plane runs on the host, outside the
   sandbox's control.

## Honest limitations

These are not fine print. They belong in the report footer too, and the project's
credibility depends on not overselling.

- **Bellwether does not prove a skill is safe.** <!-- bw-lang-ok: the §2 limitation, stated verbatim -->
  N runs produce a distribution, not a proof. A skill that behaved correctly in 50
  observed runs may behave differently in the 51st, on a different model version, or in a
  context Bellwether did not simulate. It is a strong *regression* gate and a weak
  *assurance* gate. Treat its output as evidence, not attestation.
- **It is not a runtime control.** It runs in CI, before deployment, and does not sit in
  the production request path.
- **It does not govern what a user can do.** Its value is concentrated on third-party and
  shared skills — supply chain — not on policing an individual's own local instructions.
- **It cannot fully sandbox a determined adversary.** The sandbox raises cost and captures
  evidence. It is not adequate for detonating confirmed malware.
- **Measured variance is a lower bound.** Repetitions send near-identical prompts in close
  succession, which is the ideal case for provider-side prompt caching and does not
  resemble the distribution of real deployment contexts.
- **Exfiltration detection has documented holes.** Canary matching defeats naive copying.
  It does not defeat independently-encoded chunking, interleaving across sessions, or a
  skill that instructs the model to *describe* a secret rather than reproduce it. The
  first is slated to ship as a deliberately-failing test in the acceptance corpus
  (pre-v0.1 roadmap) so the gap stays visible in CI output rather than assumed closed;
  the last is out of scope.
- **The allowlisted model channel is a residual exfiltration path.** A skill wanting to
  exfiltrate does not need `evil.com`; it puts the value in a prompt. The mitigations are
  mandatory and none of them close it. See [THREAT_MODEL.md](THREAT_MODEL.md).
- **Judged scores carry an unmeasured bias term.** Judges are blinded to metadata, never
  to content.

Explicit non-goals: not a skill marketplace, not a production firewall, not a general LLM
eval framework, not a replacement for human review of skills that touch sensitive
systems.

## Quickstart

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --group dev
uv run bellwether --help
```

Scaffold Bellwether into a repository that contains skills:

```bash
uv run bellwether init /path/to/skills-repo
uv run bellwether doctor --config /path/to/skills-repo/.bellwether/config.yaml
```

`bellwether init` writes `.bellwether/config.yaml`, `.bellwether/policy.yaml`, and a
`platform-baseline.yaml` placeholder. **The shipped config contains no model
identifiers.** Model names change, and a stale hard-coded one is the most likely source
of a confusing first-run failure, so aliases (`frontier`, `mid`, `small`) resolve through
your own config and Bellwether refuses to run against an unfilled placeholder.

`bellwether doctor` matters more than it sounds. The failure modes of this tool are mostly
environmental, and several of them fail *silently in the direction that looks clean* — a
proxy whose certificate is not trusted produces traces with zero egress, which reads as a
skill that made no network calls. Doctor probes actively rather than assuming — it will
tell you whether a Docker daemon is reachable and whether a host-side overlay is
obtainable, with the reason where either is not — and it lists the checks it cannot yet
run rather than omitting them, because a check silently left out reads as a check that
passed.

## Repository layout of a skills repo

Bellwether is designed to be dropped into a repository that *contains* skills:

```
<skills-repo>/
├── .bellwether/
│   ├── config.yaml              # global configuration
│   ├── policy.yaml              # release gates
│   ├── platform-baseline.yaml   # infrastructural allowlist
│   ├── fixtures/                # reusable workspace fixtures
│   └── baselines/               # committed baselines for regression diffing
├── skills/
│   └── <skill-name>/
│       ├── SKILL.md
│       ├── reference/           # optional supporting docs
│       ├── scripts/             # optional executables
│       └── evals/               # ALL Bellwether machinery lives here
│           ├── manifest.yaml    # declared scope
│           ├── scenarios.yaml   # scenario definitions
│           └── fixtures/
└── .github/workflows/bellwether.yml
```

A skill directory stays a valid, portable agent skill: everything Bellwether adds sits
under `evals/`, and nothing under `evals/` is ever copied into the sandbox — a skill that
can see the test machinery can behave only while observed.

A worked example is in [`examples/skills/security-review/`](examples/skills/security-review/).

### Skills packaged in an Agent Plugin

Bellwether also reads skills packaged in an [Agent Plugin](https://agent-plugins.org) bundle
(spec 1.0.0): a directory with a `plugin.json` manifest, carrying skills under `skills/`, one
per immediate child directory with a `SKILL.md`. `bellwether run <plugin-dir>` expands to the
bundled skills, each evaluated exactly as if named directly, and `bellwether changed-skills`
attributes a plugin-level change (the manifest, `mcp.json`, a client extension directory) to
every skill the plugin carries — so a PR that only rewrites the bundle's manifest still
re-evaluates what the bundle ships.

What a plugin carries beyond skills is **not evaluated** in this version. In particular a
bundled `mcp.json` declares MCP servers Bellwether never starts; every skill expanded from
such a plugin carries a problem line saying so, because the verdict covers the skill files
alone and an unmentioned component would read as one that ran clean.

## What is built

| Area | State |
|---|---|
| **Foundation** — scaffolding, module boundaries, CI, determinism primitives; `config`/`policy`/`manifest`/`scenario` loading; `init` / `doctor` / `version` | done |
| **Skill & trace** — skill parsing + the three digests, payload allowlist, ARF schema, JSONL writer/reader, incomplete-trace detection | done (WP-2, WP-3) |
| **Sandbox** — zones, fixture materialisation, payload staging, isolation profile; overlay mount + whiteout-aware upper-dir diff; container lifecycle | done (WP-4) |
| **Capture** — host-owned event sink (Plane A), per-zone filesystem overlay (Plane B), the coverage block | done (WP-5) |
| **Harness** — `api-loop` adapter: agent loop, sandboxed tools, scripted provider, golden trace | done (WP-6) |
| **Analysis** — canonicalization + epoch anchoring, platform baseline, assertions + Declared-vs-Observed, metrics (Wilson/Pocock, risk-weighted Jaccard, trajectory clustering, BCI), verdict engine | done (WP-7–11) |
| §16.4 precondition check (refuse an unsatisfiable policy *before* spending) | done — wired into `run` (refuses before the executor is built) and `doctor` (per-profile rows) |
| **Reporting** — schema-versioned `summary.json`, the §13.8 figures, the Markdown PR comment, a self-contained theme-aware HTML report | done (WP-12, §17.4) |
| **Orchestration** — analysis orchestrator (trace → metrics → gates → verdict → artifact tree) and the container execution driver; first-light checkpoint reached | done |
| **Recording proxy** (WP-13) — egress classification + default-deny allowlist + per-run caps; credential isolation (scoped token, proxy-side injection, leak guard); mitmproxy sidecar; internal-bridge isolation with no route out but the proxy; live interception proven on CI | done |
| **Proxy in the live run** — dual-homed sidecar per repetition, CA mounted so TLS is intercepted, egress recorded as Plane D of the trace (`egress.image` turns it on) | done |
| **Live model client** — Anthropic Messages API behind the `ModelClient` seam | done |
| **`bellwether run` from the CLI** — resolve → live client → matrix → verdict → artifact tree | done |
| **CI integration** — `bellwether changed-skills`, `bellwether pr-comment`, the shipped GitHub Action (only changed skills, paid run label-gated), per-run evidence uploaded as an artifact | done |
| **Live verdict on CI** — a benign skill reaching `ready` against a real model, egress observed | proven |
| **Canaries** — mint, decode-then-match, destination classification, redaction; planted in live runs (env var + file slots) and scanned across output, DNS names, tool args, egress URLs *and* bodies, written files, **and every composed model request** (§10.4.1 read-state grading); a leak gates the verdict (`security_runtime.canaries`), an unread canary in model context gates it too (`security_runtime.canary_reads`); credentials plane `full` | done (WP-16 capture story; corpus skills land with WP-20) |
| CA trust chain — §9.2 mechanism table, install env/commands, confirm predicate | done (WP-14 core); live doctor probe pending |
| Controlled DNS resolver — default-deny allowlist, NXDOMAIN, query log, canary-in-labels scan; sidecar wired into the executor (`dns.image`), Plane E in the trace; a lookup outside the allowlist gates the verdict (`security_runtime.dns`) | done (WP-15) |
| Static scanner (§15) · probe suite (§7.6) · coexistence matrix (§7.4) · baseline diffing (§17.5) | **not implemented** — the CLI commands refuse with exit 3 and name the work package, rather than emitting an empty clean-looking result |
| **Noise-floor calibration** — Plane-A-only dispersion proven exactly 0 on real containers (sequentially and under concurrent load); the cross-plane residual published as `noise_floor` in every `summary.json`; dispersion at or below the floor reported as `at_noise_floor`, never a precise small number | done (WP-19) |
| **Plane precedence (§10.8)** — `trace_inconsistency` produced only where two planes are in-domain and fidelity supports the absence being read; a benign run at overlay-diff fidelity yields zero findings, proven on a real container | done (WP-18) |
| **Acceptance corpus — security slice** — `canary-thief`, `dns-thief`, `legit-credential-reader` under `tests/corpus/`, driven through the real pipeline with §25 verdicts asserted in CI; the §10.4.1 false-positive guard proven | done (WP-20 security slice) |
| `claude-code` harness adapter (WP-17) · corpus & acceptance (WP-20, the remaining eight skills) | remaining |

Work packages are defined in [docs/BUILDPLAN.md](docs/BUILDPLAN.md); the specification
they implement is [docs/spec.md](docs/spec.md). Where the implementation had to resolve
something the spec leaves ambiguous or gets wrong, the resolution is recorded in
[docs/spec-notes.md](docs/spec-notes.md).

## Development

```bash
uv sync --group dev

uv run ruff check .                     # lint
uv run ruff format .                    # format
uv run mypy                             # types, strict
uv run lint-imports                     # module boundaries
uv run python tools/language_lint.py    # verdict vocabulary
uv run python tools/pin_lint.py         # supply-chain pinning
uv run pytest -m "not docker"           # runs offline, with no API key

# The container integration tests need a Docker daemon and root, because mounting the
# host-side overlay upper directory is the privilege the host has and the container
# does not — the capture architecture in one line.
sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker
```

Six rules are enforced by CI rather than by convention, because each is a rewrite if
retrofitted:

- **Module boundaries.** The dependency graph flows
  `config → skill → scan → sandbox → harness → capture → trace → assertions → metrics →
  verdict → report → cli`, is acyclic, and `metrics` never imports `verdict`.
- **Determinism.** Sorted sets, rounding at serialisation only, no reliance on `hash()`
  ordering, sorted file walks, seeded and recorded RNG. See `bellwether.determinism`.
- **No hard-coded model identifiers.** A literal model string outside a user's own
  `config.yaml` is a bug.
- **Language discipline.** The verdict vocabulary must not imply proof;
  `tools/language_lint.py` fails the build on the words that would.
- **Supply-chain pinning.** Every third-party GitHub Action is pinned to a full commit
  SHA, every container image (in workflows *and* Dockerfile `FROM` lines) to a `@sha256:`
  digest; `tools/pin_lint.py` fails the build on a mutable tag. A tool about supply chain
  must not pull mutable tags in its own CI. Python dependencies are hash-pinned in
  `uv.lock` (`uv sync --frozen` verifies every hash). Digest-pinning the runtime
  sandbox/egress image, by contrast, is a **non-blocking advisory**, not a hard refusal: a
  moving tag makes two evaluations non-comparable, so Bellwether reports an advisory when the
  configured image is a floating tag but still runs — `examples/live` deliberately uses one.
- **Types.** `mypy --strict` over the whole package.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the detail, [docs/STATUS.md](docs/STATUS.md)
for where the build is, and [THREAT_MODEL.md](THREAT_MODEL.md) for what this does and
does not defend against.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
