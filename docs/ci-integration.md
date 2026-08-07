# Running Bellwether on a pull request

This is the intended end-to-end shape: a skill changes in a pull request, Bellwether
evaluates it, and the verdict both lands as a comment and gates the merge. Some of the pieces
below are built and tested; one is not yet proven end to end. Both are called out.

## The flow

1. A pull request adds or changes a skill (in a skill repo, or a shared plugin registry).
2. A GitHub Actions job runs `bellwether run` on the changed skill. This is where the model is
   actually called — many times per scenario, in the instrumented sandbox — so it needs a
   real API key, supplied as a **repository secret**.
3. `bellwether run` writes the artifact tree, including `report/pr_comment.md` and
   `report/report.html`, and exits `0` for `ready`/`conditional` or `2` for `not_ready`.
4. `bellwether pr-comment` posts (or updates in place) the rendered comment on the PR, and the
   HTML report is uploaded as a downloadable CI artifact.
5. Because the job fails on exit `2`, a `not_ready` verdict shows as a failed required check
   and blocks the merge.

## The key never enters the sandbox

The API key is a secret held by the **harness on the CI runner**, not by the skill under
evaluation. The skill runs in the container with a worthless, per-run *scoped token*; the
recording proxy swaps in the real key only for legitimate model calls, on the wire, and the
container never sees it (§3.3). A malicious skill therefore cannot read the key even though
the same job holds it — which is the property the `sneaky-exfiltrator` example is built to
probe.

## A workflow template

This is a template to adapt, not an active workflow in this repository. Pin every `uses:` to a
commit SHA in a real workflow — the repository's `pin_lint` enforces that on the workflows it
ships.

```yaml
name: bellwether
on: pull_request

permissions:
  contents: read
  pull-requests: write   # so the report comment can be posted

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>       # pin to a SHA
      - uses: astral-sh/setup-uv@<sha>     # pin to a SHA

      - name: Evaluate the changed skill
        id: run
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: uv run bellwether run path/to/skill --out .bellwether-out

      - name: Upload the HTML report
        if: always()
        uses: actions/upload-artifact@<sha>  # pin to a SHA
        with:
          name: bellwether-report
          path: .bellwether-out/**/report/report.html

      - name: Comment the verdict on the PR
        if: always()
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          uv run bellwether pr-comment \
            "$(dirname "$(find .bellwether-out -name pr_comment.md | head -n1)")/.." \
            || uv run bellwether pr-comment .bellwether-out/*/
```

`bellwether pr-comment` reads `report/pr_comment.md` from the eval directory you point it at,
resolves the repository and PR number from the GitHub Actions environment
(`GITHUB_REPOSITORY`, `GITHUB_REF`), and upserts the comment — a re-run on the same PR edits
the previous comment rather than stacking a new one. Preview what it would post, with no token
and no network, using `--dry-run`.

## Status

- **`bellwether pr-comment`** — built and tested (offline, through an injected transport). The
  idempotent upsert and the token-only-in-the-auth-header guard are pinned by unit tests.
- **`bellwether run` on a live container** — wired and tested offline, but a real run against a
  live model in a container has not yet been exercised end to end on CI. Until it is, treat the
  workflow above as the target shape rather than a proven pipeline. See `docs/STATUS.md`.
