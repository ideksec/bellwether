# Contributing

Bellwether is built from [docs/spec.md](docs/spec.md), in the order set out in
[docs/BUILDPLAN.md](docs/BUILDPLAN.md). The spec is the source of truth for *what*; the
build plan is the source of truth for *order*, and for what "done" means at each step.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --group dev
uv run pytest -m "not docker"
```

Every test runs offline, with no API key, except where a test is explicitly marked
otherwise (`docker`, `network`). That is a requirement, not a convenience: contributors
without provider credentials must be able to work on the whole analysis pipeline.

## The full check, as CI runs it

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run lint-imports
uv run python tools/language_lint.py
uv run python tools/pin_lint.py
uv run pytest -m "not docker"
```

All six checks plus the offline suite, in the order CI runs them. Run each explicitly and read the
output — a silently-skipped check is how a red build looks green.

## The container integration tests

The tests marked `docker` run small non-agentic container workloads with known behaviour
and assert the capture plane records exactly the expected events (§24). They need a
Docker daemon, and they need **root** — mounting the host-side overlay upper directory is
the privilege the host has and the container does not, which is the whole capture
architecture in one line (§10.0).

```bash
sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker
```

They skip with a stated reason where either is missing. The interpreter is invoked
directly rather than through `uv run`, because `uv` as root would want to resolve and
possibly rewrite an environment that belongs to the normal user. CI runs them as a separate job
rather than letting them skip inside the main one: a suite that goes green with these
quietly absent is exactly the clean-looking failure this project exists to distrust, so
the job also asserts they were collected.

In Claude Code on the web, `.claude/hooks/session-start.sh` starts the daemon at session
start. Note that not every container registry is reachable under a restrictive egress
policy — registries that redirect blobs to a CDN often are not — so
`BELLWETHER_TEST_IMAGE` selects the image and defaults to one that serves its own blobs.

## Six rules that are enforced mechanically

Each of these is cheap to hold from the first commit and a rewrite to retrofit. That is
why they are in CI rather than in a style guide.

### 1. Module boundaries

The package is a layered stack:

```
config → skill → scan → sandbox → harness → capture → trace
       → assertions → metrics → verdict → report → cli
```

The graph must stay acyclic and flow one way. `metrics` must never import `verdict` —
metrics that know about policy stop being measurements and start being arguments. Nothing
except `verdict`, `report` and `cli` may import policy types. `config` must not touch the
network; `sandbox` must not know about models.

Contracts live in `.importlinter` and run as `uv run lint-imports`.

### 2. Determinism

Given identical input traces, Bellwether's output — excluding timestamps and IDs — must
be byte-identical. This is not achievable by intention; it needs explicit rules, and
`bellwether.determinism` is where they live:

- all sets serialised in sorted order;
- floats rounded **at serialisation** (`round(x, 6)`), never at computation;
- no reliance on `hash()` ordering — CI sets `PYTHONHASHSEED=0` *and* nothing may depend
  on it;
- dict key order fixed by schema, not insertion;
- sorted file walks when computing digests;
- seeded and recorded RNG, so an evaluation is reproducible from its own artifacts.

If you are adding something that serialises, sorts, or randomises, use the helpers rather
than reimplementing them nearby.

### 3. No hard-coded model identifiers

Model names change. Aliases (`frontier`, `mid`, `small`) resolve through the user's own
`config.yaml`, and `resolve_model_id` is the only place an identifier enters the system.
A literal model string anywhere else — including in a default, a test fixture that gets
copied, or a docstring example — is a bug.

### 4. Language discipline

The verdict vocabulary must not imply proof. Bellwether reports `ready` / `conditional` /
`not_ready`, meaning "met the configured gates on the evidence collected". It never
reports that anything is safe, secure, verified, approved, or certified, because N runs
produce a distribution and a distribution is not a proof.

`tools/language_lint.py` enforces this over string literals, docstrings, CLI help and
shipped templates, and fails the build. Where a banned word genuinely belongs — quoting
the limitations in §2, for instance — mark the line with a reason:

```python
"Bellwether does not prove a skill is safe"  # bw-lang-ok: quoting the §2 limitation
```

A marker without a reason is itself an error. The point is that someone had to think.

### 5. Supply-chain pinning

Bellwether's thesis is that a supply-chain artifact is trustworthy only when what you
review is what runs. That has to hold for the project's own plumbing, or the tool is
arguing against itself. So every supply-chain input is pinned to an immutable digest:

- every third-party GitHub Action is pinned to a full 40-hex commit SHA, not a tag
  (`actions/checkout@fbc6f39… # v5`); the trailing `# vN` comment is what Dependabot reads
  to bump the pin;
- every container image in the project's own plumbing is pinned by `@sha256:` digest — in CI
  and in the test defaults; for the *runtime* sandbox/egress image, digest-pinning is a
  non-blocking advisory rather than a config-validation refusal — a moving tag makes two
  evaluations non-comparable, so it is reported, not rejected (`examples/live` intentionally
  uses a moving tag);
- Python dependencies are hash-pinned in `uv.lock`, and `uv sync --frozen` verifies every
  recorded hash on install;
- `uv` itself and the Python version are pinned in CI.

`tools/pin_lint.py` enforces the first two over the workflow files and fails the build on a
mutable tag. `.github/dependabot.yml` keeps the pins from going stale — a pin that never
updates is its own risk. When you add an action or an image, pin it; the lint will remind
you if you forget.

### 6. Types

`mypy --strict` runs over the whole package. The specification requires it on `metrics`,
`trace`, `verdict` and `capture` "at minimum"; holding the line everywhere from the start
is cheaper than drawing a boundary and defending it.

## Errors are sentences

Configuration errors name the file, the path within it, and the allowed values. A stack
trace is not an error message. Most users meet this project for the first time through a
YAML error, so `bellwether.config.render` gets more care than its size suggests — and
every deliberately-malformed document has a test asserting its message is readable.

## Working through the build plan

- Do not start a work package whose predecessors are not green.
- **WP-7 (epoch anchoring) and WP-19 (noise floor) are a pair.** WP-19 is the only test
  that proves WP-7 works. A wrong WP-7 silently corrupts the project's differentiating
  metric, and everything built on top of it will look plausible.
- **WP-10's property tests are the specification.** If a property test and the prose
  disagree, the prose is probably right and the test encodes a misreading — but check
  both, and record the resolution in the spec.
- Several numbers in the spec are provisional and flagged as such: the trajectory cluster
  threshold, the look points and thresholds, and the cost table. Treat them as inputs to
  calibrate, not constants.
- Harness CLI flags and hook APIs change. Read the current documentation for the harness
  you are adapting; do not trust the spec's description of another project's interface.

## Before you start

[docs/STATUS.md](docs/STATUS.md) is where the build is: what is done, what is next, what
is outstanding, and the environment quirks that have already cost time — the Docker
daemon that does not start itself, the registries that are unreachable, and the CI checks
that can go stale against an older commit than the one that would merge.

## Pull requests

- One work package, or one coherent slice of one, per pull request.
- Say which section of the spec the change implements, and which "done when" criteria it
  meets.
- If you found the spec wrong, say so in the pull request and change the spec in the same
  change. A spec that quietly diverges from the code is worse than either alone.
- New behaviour needs a test that would fail without it. New *user-facing* behaviour needs
  a test that reads like the sentence a user would say.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
