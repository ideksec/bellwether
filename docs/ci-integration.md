# Running Bellwether on a pull request

A skill changes in a pull request, Bellwether evaluates it, and the verdict both lands as a
comment and gates the merge. The workflow that does this ships in this repository at
[`.github/workflows/bellwether.yml`](../.github/workflows/bellwether.yml); copy it into a
skill repository and adapt it. Some pieces are built and tested; one is not yet proven end to
end, and that is called out below.

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
5. `bellwether pr-comment` posts (or updates in place) the rendered comment on the PR. Because
   the job propagates the exit code, a `not_ready` verdict shows as a failed required check
   and blocks the merge.

## Only changed skills

A skill is a directory with a `SKILL.md`. `bellwether changed-skills` reads a list of changed
paths (from `git diff --name-only`) and returns the skill directory each belongs to — a change
to `foo/evals/manifest.yaml` is attributed to the skill at `foo/`, because a skill's declared
scope lives beside its `SKILL.md`. A change outside every skill (the harness, a doc) maps to
nothing; a skill whose `SKILL.md` was deleted is not returned. Two changes in one skill
collapse to one entry, so each affected skill runs exactly once.

```bash
git diff --name-only origin/main...HEAD | bellwether changed-skills
```

## No key, no problem (the job still passes)

The live evaluation is gated on the secret being present: if `ANTHROPIC_API_KEY` is unset, the
workflow reports which skills it *would* evaluate and exits `0`. So a fork, or a repository
that has not provisioned a key yet, stays green — the changed-skills detection still runs, but
the model is not called.

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
  a key is present.
- **`bellwether run` on a live container** — wired and tested offline, but a real run against a
  live model in a container has not yet been exercised end to end on CI. Until it is, treat the
  live branch of the workflow as the target shape rather than a proven pipeline. See
  `docs/STATUS.md`.
