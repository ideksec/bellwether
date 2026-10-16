# Running Bellwether on a pull request

A skill changes in a pull request, Bellwether evaluates it, and the verdict both lands as a
comment and gates the merge. The workflow that does this ships in this repository at
[`.github/workflows/bellwether.yml`](../.github/workflows/bellwether.yml); copy it into a
skill repository and adapt it. What is proven and what is still narrow is called out under
**Status** below.

## Gate 0: the static scan, on every pull request

[`.github/workflows/bellwether-scan.yml`](../.github/workflows/bellwether-scan.yml) runs before
any paid evaluation, on every pull request and on `main`, with no secret and no label. It reads
skills and runs none of them, so it costs nothing — which is why it scans **every** skill under
your skill roots, not only the changed ones: a code-scanning analysis that covered only the
changed skills would show every other skill's open alerts as "fixed" on that pull request.

1. `git ls-files -z -- <roots> | bellwether changed-skills -z --under <root>` lists the skills.
2. **Gitleaks** runs in its own digest-pinned container, offline (`--network none`), over the
   skill roots, and writes SARIF. Bellwether **never runs a scanner itself** — the config that
   would name a command lives in the checkout a pull request edits (see
   `docs/spec-notes.md`, "§15 — delegation reads scanner output").
3. `bellwether scan --skills-from … --policy … --scanner-sarif gitleaks.sarif --sarif … --markdown …`
   holds each skill to the static gate of the profile its criticality selects — the same profile
   `bellwether run` judges it under — and merges the Gitleaks results in. Gitleaks grades
   nothing, so the policy floors it: `gates.static.scanner_min_severity: {gitleaks: high}`.
4. The summary goes to the job page; the SARIF goes to the **Security tab** (skipped for a fork,
   whose token cannot write security events) and to an artifact anyone can download.
5. Last, after both uploads: a finding above a skill's threshold fails the check (exit 2).

To add another scanner (Semgrep, Trivy, Bandit), run it in its own step, write SARIF, and pass
it with another `--scanner-sarif`. Run it from the repository root over a *relative* path, so
its SARIF names files the way Bellwether attributes them; a result outside a skill, or under a
skill's `evals/` machinery, is reported in a note and never attributed. To make a scanner
mandatory, name it in `gates.static.required_scanners`: a run without its SARIF is refused.

```bash
bellwether scan examples/skills/workspace-stats                 # one skill, default threshold
bellwether scan --skills-from skills.txt --policy .bellwether/policy.yaml \
  --scanner-sarif gitleaks.sarif --sarif static.sarif --markdown summary.md
```

## The flow

1. A pull request adds or changes a skill (in a skill repo, or a shared plugin registry).
2. The workflow computes the changed files against the PR base and runs `bellwether
   changed-skills` to map them to the skill directories affected — so **only skills the PR
   touched are evaluated**, never every skill already in the repo.
3. For each changed skill it runs `bellwether run`, which calls the model many times per
   scenario in the instrumented sandbox. That needs a real API key, supplied as the
   `ANTHROPIC_API_KEY` **repository secret**.
4. `bellwether run` writes the artifact tree, including `report/pr_comment.md` and
   `report/report.html`, and exits `0` for `ready`/`conditional` or `2` for `not_ready`.
5. `bellwether pr-comment` posts (or updates in place) the rendered comment on the PR. Each
   evaluation — a skill on its targets, read from the `summary.json` beside the report — owns its
   own comment, so two harnesses or two changed skills on one PR each keep their verdict visible
   and a re-run edits only its own. Pass it the evaluation directory. Because
   the job propagates the exit code, a `not_ready` verdict shows as a failed required check
   and blocks the merge.

## Only changed skills

A skill is a directory with a `SKILL.md`. `bellwether changed-skills` reads a list of changed
paths (from `git diff --name-only`) and returns the skill directory each belongs to — a change
to `foo/evals/manifest.yaml` is attributed to the skill at `foo/`, because a skill's declared
scope lives beside its `SKILL.md`. A change outside every skill (the harness, a doc) maps to
nothing; a skill whose `SKILL.md` was deleted is not returned. Two changes in one skill
collapse to one entry, so each affected skill runs exactly once.

Skills packaged in an [Agent Plugin](https://agent-plugins.org) bundle (a directory with a
`plugin.json`, skills under `skills/`) are attributed the same way where the change is inside
one skill — and a *plugin-level* change (the manifest, `mcp.json`, a client extension
directory) is attributed to **every** skill the plugin carries, because there is no per-skill
attribution for it and mapping it to nothing would read as "no skills changed" on a PR that
rewrote the bundle.

```bash
git diff --name-only -z origin/main...HEAD | bellwether changed-skills -z --under skills
```

`--under` (repeatable) keeps only skills inside your real skill roots. Use it whenever the
repository also holds skill-shaped directories that are not skills — test fixtures, templates.
This repository keeps deliberately hostile fixtures under `tests/`, and before `--under` a
labelled pull request touching one would have spent tokens evaluating it. A root that names
nothing inside the checkout (an absolute path, a `..` escape) is refused, not read as "no
skills changed".

## Opt-in per PR, so nothing spends by surprise

The live evaluation costs model tokens, so it is **opt-in per pull request**: it runs only when
the PR carries the `bellwether-run` label *and* the `ANTHROPIC_API_KEY` secret is set. A plain
PR — no label, or no key — just reports which skills it *would* evaluate and exits `0`. So a
fork, an un-provisioned repository, or any everyday PR stays green with no spend; the
changed-skills detection still runs. To see a real evaluation, add the `bellwether-run` label to
the PR.

This repository's workflow points at its own cheap smoke config
([`examples/live/`](../examples/live/) — api-loop + Haiku, one look of 6, a hard token cap). In a
real skill repository, point `BELLWETHER_CONFIG`/`BELLWETHER_POLICY` at your own `.bellwether/`.

A **second workflow**,
[`.github/workflows/bellwether-claude-code.yml`](../.github/workflows/bellwether-claude-code.yml),
runs the same changed skills under the **`claude-code`** harness — the real Claude Code CLI
headless *inside* the sandbox — against a real model, using
[`examples/live/config-claude-code.yaml`](../examples/live/config-claude-code.yaml). It is gated
identically (the `bellwether-run` label plus the key), and builds the claude-code sandbox image
and the two sidecars before the run. On a labelled PR that changes a skill, both workflows run, so
the skill is evaluated under both harnesses side by side.

## The key never enters the sandbox

The API key is a secret held by the **harness on the CI runner**, not by the skill under
evaluation. The skill runs in the container with a worthless, per-run *scoped token*; the
recording proxy swaps in the real key only for legitimate model calls, on the wire, and the
container never sees it (§3.3). A malicious skill therefore cannot read the key even though the
same job holds it — which is the property the `sneaky-exfiltrator` example is built to probe.

## Status

- **`bellwether changed-skills`** and **`bellwether pr-comment`** — built and tested offline
  (the latter through an injected transport; the idempotent upsert and the
  token-only-in-the-auth-header guard are pinned by unit tests).
- **The workflow** — ships and is wired for real, but its live-evaluation branch only runs when
  a key is present *and* the PR carries the `bellwether-run` label.
- **`bellwether run` on a live container** — **proven end to end on CI.** A benign skill has
  reached `ready` on a real labelled pull request against a live model, in a sandbox behind the
  recording proxy with egress observed, and every run's evidence was uploaded as an artifact.
- **Gate 0** — `bellwether-scan.yml` is executed step by step by
  `tests/test_scan_workflow.py`: the real Gitleaks image and the real `scan` run against a scratch
  repository, a clean one passes, a planted token fails the gate after both uploads (and the
  Security-tab upload is skipped for a fork). Running it found a defect no linter did — the
  runner's `bash -e` aborted the scan step on exit 2 before the summary and the SARIF flag were
  written.
- **What is still narrow.** The live proofs cover a handful of skills on one cheap target per
  harness (`api-loop` + Haiku; `claude-code` + Haiku), at a single look of 6. Both harnesses have
  run live on labelled pull requests (#65, #102). See `docs/STATUS.md` for the current boundary,
  and the README's "What the live verdict gates today" for which gates are actually scored.
