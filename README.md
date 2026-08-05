# Bellwether

A CI/CD harness for AI agent skills.

Bellwether executes a candidate skill many times, across multiple models and vendors,
inside an instrumented sandbox; captures a deterministic record of everything the agent
actually *did*; measures how much that behaviour varies between runs; and renders a
release verdict against a policy the repository owner controls.

**The name is the thesis.** A bellwether is the lead sheep whose bell signals that the
flock is about to move. It warns; it does not vouch.

---

## Status

**Pre-v0.1. Under construction.** The scaffolding, configuration layer, skill parser,
trace format, sandbox, the first two capture planes (harness events, filesystem by
zone), and the `api-loop` reference harness adapter are built and tested. The
`claude-code` adapter, the network planes, metrics and the verdict engine are not.

`bellwether run` is not usable yet and says so, naming the work package that brings it,
rather than printing an empty result that would read as a clean run.

**[docs/STATUS.md](docs/STATUS.md) is the current state of the build** — what is done,
what is next, what is outstanding, and what a new contributor needs to know about the
environment. [docs/BUILDPLAN.md](docs/BUILDPLAN.md) has the ordering.

New here? [pitch.md](pitch.md) is the short version of what this is and why.

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
  first ships as a deliberately-failing corpus test so the gap is visible in CI output
  rather than assumed closed; the last is out of scope.
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

## What is built

| Area | State |
|---|---|
| Project scaffolding, module boundaries, CI, determinism primitives | done |
| `config.yaml`, `policy.yaml`, `evals/manifest.yaml`, `evals/scenarios.yaml` loading and validation | done |
| `bellwether init`, `bellwether doctor`, `bellwether version` | done |
| Skill parsing, the three digests, payload allowlist, executable inventory | done (WP-2) |
| ARF trace schema, JSONL writer and reader, incomplete-trace detection | done (WP-3) |
| Sandbox host side: zones, fixture materialisation, payload staging, identifiers, isolation profile | done (WP-4) |
| Sandbox container backend: overlay mount, whiteout-aware upper-dir diff, container lifecycle | done (WP-4) |
| Capture: host-owned event sink (Plane A), per-zone overlay filesystem capture (Plane B), coverage block | done (WP-5) |
| `api-loop` harness adapter: agent loop, sandboxed tools, scripted provider, golden trace | done (WP-6) |
| Epoch anchoring, platform baseline, assertions | WP-7 (next) – WP-9 |
| `claude-code` harness adapter | WP-17 |
| Metrics, verdict engine, reporting | WP-10 – WP-12 |
| Recording proxy, CA trust chain, DNS resolver, canaries | WP-13 – WP-16 |
| Corpus and acceptance | WP-20 |

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
uv run pytest -m "not docker"           # runs offline, with no API key

# The container integration tests need a Docker daemon and root, because mounting the
# host-side overlay upper directory is the privilege the host has and the container
# does not — the capture architecture in one line.
sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker
```

Five rules are enforced by CI rather than by convention, because each is a rewrite if
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
- **Types.** `mypy --strict` over the whole package.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the detail, [docs/STATUS.md](docs/STATUS.md)
for where the build is, and [THREAT_MODEL.md](THREAT_MODEL.md) for what this does and
does not defend against.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
