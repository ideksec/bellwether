# Live smoke config

The cheap configuration for a *live* run — the one that proves `bellwether run` works against
a real model end to end, without spending much.

- **`config.yaml`** — the `anthropic` provider (key from `ANTHROPIC_API_KEY`, read by the host
  and never placed in the sandbox), the smallest model (`haiku`), and a small digest-pinned
  sandbox image.
- **`policy.yaml`** — one `api-loop`/`anthropic`/`haiku` target at a single look of 6 (~$0.20–0.40
  of Haiku per skill), with the egress/DNS gates demoted to advisory because this executor does
  not yet wire the recording proxy (§25).

## Running it

The live run mounts an overlay for host-side capture (§10.0), which needs root, so it runs
under `sudo` with the key preserved:

```bash
sudo --preserve-env=ANTHROPIC_API_KEY .venv/bin/bellwether run \
  examples/skills/benign-note-taker \
  --config examples/live/config.yaml \
  --policy examples/live/policy.yaml \
  --max-tokens 60000 \
  --out .bellwether-out
```

On CI this is driven by [`.github/workflows/bellwether.yml`](../../.github/workflows/bellwether.yml),
gated on the `ANTHROPIC_API_KEY` secret and the `bellwether-run` PR label so it never spends by
surprise. See [`docs/ci-integration.md`](../../docs/ci-integration.md).

This is the project's own smoke setup; a real skill repository keeps its own config under
`.bellwether/`.
