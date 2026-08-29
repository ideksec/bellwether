# CLAUDE.md — orientation for an agent working on Bellwether

You are working on **Bellwether**, a CI/CD gate for AI agent *skills*: run a candidate skill N times
in a hardened sandbox, capture what it actually did across several evidence planes, measure how
consistent that behaviour is, and render a `ready` / `conditional` / `not_ready` verdict backed by
inspectable evidence. The thesis is deliberately humble — a strong *regression* gate, a weak
*assurance* gate. Do not let the vocabulary drift toward proof (see the language rule below).

## Start every session here

1. **`docs/STATUS.md`** — the live state of the build and, at the top, **"What's next — remaining
   work, in recommended order."** This is the single source of truth for *where we are* and *what to
   pick up*. Read it first, every time.
2. **`docs/BUILDPLAN.md`** — the order and the "done-when" for each work package. Note the
   progress/re-ordering note at the top of Phase B: the build inserted unnumbered integration work,
   so the remaining order differs from the raw WP numbers.
3. **`docs/spec.md`** — the specification (revision 3), the source of truth for *what*. Read the
   sections relevant to whatever you are building.
4. **`docs/spec-notes.md`** — every deliberate divergence from the spec, with reasoning. **Read the
   relevant entry before changing anything in the skill, sandbox, capture, config, or report layers**,
   and add an entry when you diverge.
5. `CONTRIBUTING.md` — setup, the exact CI commands, and the six enforced rules in detail.

## Where the build is (one line; STATUS has the detail)

Phase A and the recording-proxy spine of Phase B are done, and the live loop closes end to end: on a
real PR, a changed skill is detected, run 6× in a sandbox behind a dual-homed recording proxy that
observes its egress, scored, and posted back — a benign skill has reached **`ready` on CI against a
live model**, with per-run evidence uploaded as an artifact. The DNS resolver is wired into the
executor, canaries are planted and scanned end to end, the §16.4 precondition check is wired into
`run`/`doctor` (an unsatisfiable policy refuses before spending), and **canary leaks now gate the
verdict** (`security_runtime.canaries` — a skill that exfiltrates a planted canary cannot reach
`ready`), and the **DNS gate is scored** (`security_runtime.dns`, with the live smoke wiring the
resolver so the labelled run keeps `ready` on observed evidence). The model-API canary
channel is scanned and scored (`security_runtime.canary_reads`; credentials plane `full`). What
remains is *breadth*: the `claude-code` adapter and the acceptance corpus (the
`credential_read_undeclared` disposition waits on the read-capture plane). The noise floor is calibrated (WP-19):
Plane-A dispersion is proven exactly 0 on real containers and the residual is published in every
`summary.json`. The §10.8 precedence matrix is implemented (WP-18): `trace_inconsistency` is
raised only where two planes are in-domain at supporting fidelity, and a benign overlay-diff run
yields zero findings.

## How we work — the cadence (one brick, one PR)

1. Build the code **and its tests** for one well-scoped brick.
2. Run **all six checks** (below) plus the offline suite — each explicitly, and read the output.
   A silently-skipped check is how a red build looks green.
3. Update docs: `docs/STATUS.md` always (state + "What's next"), `docs/spec-notes.md` on any
   divergence, `README.md` when a user-visible capability changes.
4. Commit with a clear message. Keep the `Co-Authored-By: Claude <noreply@anthropic.com>` trailer —
   this project is openly built with agentic assistance and does not hide it — but do **not** append
   session URLs or emoji; they are noise in a public history.
5. Push to the feature branch this session is assigned. **Never push to `main`.**
6. Open a PR, watch CI to green, fix anything red before moving on.
7. **After the PR merges, restart the branch from the fresh main**
   (`git fetch origin main && git checkout -B <branch> origin/main`) before the next brick — do not
   stack a new brick on already-merged history.

## The six mechanically-enforced checks (run before every commit)

```bash
uv run ruff check .                     # lint
uv run ruff format --check .            # format  (this one has bitten us — run it explicitly)
uv run mypy                             # types, strict, whole package
uv run lint-imports                     # module boundaries (config→…→cli, acyclic; metrics ⊥ verdict)
uv run python tools/language_lint.py    # verdict vocabulary (bans safe/secure/verified/approved/certified/guarantee/prove/ensure in user-facing strings; "vouch" is allowed only in the negative — the project's own "does not vouch" thesis)
uv run python tools/pin_lint.py         # supply-chain pinning (SHA-pinned actions, digest-pinned images)
uv run pytest -m "not docker"           # the offline suite — no API key, no daemon
```

Container tests (need a Docker daemon **and root**, because mounting the host-side overlay is the
privilege the host has and the container does not):

```bash
sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker
```

## Non-negotiable disciplines (these have caught essentially every defect so far)

- **Run it. A passing test is not evidence.** Almost every bug found in this project looked like it
  worked and had a green test asserting the wrong thing. Execute the real thing — a container, a
  reproduction script, a CI step — before believing it.
- **Observation beats declaration.** A claim that cannot be evaluated is reported `not_evaluable`,
  never silently passed. A missing plane must read as "unavailable because X," never as a clean run.
- **Determinism (§24).** Sorted sets, rounding at serialisation only, no reliance on `hash()`
  ordering, sorted file walks, seeded and recorded RNG. `Date.now`/random are unavailable in some
  paths by design. Same input → same bytes; several tests byte-compare committed artifacts.
- **No hard-coded model identifiers.** Aliases (`frontier`, `mid`, `small`) resolve through config.
  A literal model string outside a user's own `config.yaml` is a bug.
- **Language discipline.** The verdict/report vocabulary must not imply proof. The lint fails the
  build on the banned words; if a limitation must state one verbatim, mark it `<!-- bw-lang-ok: … -->`.
- **Supply-chain pinning.** Every third-party GitHub Action → full commit SHA; every image (workflows
  *and* Dockerfile `FROM`) → `@sha256:` digest. A tool about supply chain must not pull mutable tags.

## Environment (Claude Code on the web)

- `.claude/hooks/session-start.sh` starts the Docker daemon at session start.
- The container tests skip with a stated reason where the daemon or root is missing — that is honest,
  not a pass. The **recording-proxy sidecar image build is CI-only** (it needs open egress to `pip
  install mitmproxy`); tests that build it are gated on `CI` and skip locally.
- Docker **bind-mount source paths must be absolute** — a relative path is read as a named volume and
  fails at container start (this cost a live run once; `execute()` calls `.resolve()`).
- `BELLWETHER_TEST_IMAGE` selects the sandbox test image (defaults to one that serves its own blobs,
  so it is pullable under a restrictive egress policy).
- The session is **ephemeral**: commit and push anything worth keeping before the session ends.

## Cost discipline (live model runs)

A live evaluation spends real tokens and is **opt-in per PR**: it runs only when a PR both changes a
skill *and* carries the `bellwether-run` label. The `examples/live/` config is the cheap smoke setup
(api-loop + Haiku, one look of 6, a `--max-tokens` ceiling, ~$0.30/run). **Do not trigger a paid run
without explicit user approval** — and note that pushing to a labelled skill-changing branch
re-triggers one.

## The module layering (enforced by `lint-imports`)

`config → skill → scan → sandbox → harness → capture → trace → assertions → metrics → verdict →
report → cli`. Acyclic; `metrics` must never import `verdict`; only `verdict`/`report`/`cli` may
import policy types. `bellwether.determinism` and `bellwether.errors` are shared leaves everything
may use.
