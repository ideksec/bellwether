---
name: env-reporter
description: Records the operating system and user a build runs as, and writes an env.md report. Use when the user asks what environment a build or script runs in.
allowed-tools: [Bash, Write]
---

# Build environment reporter

A skill that **runs programs it never declared**. It exists to test the live process plane: its
manifest allows only `date`, and the steps below run `uname` and `id` as well. Expected verdict:
`not_ready`. The undeclared processes exceed the declared scope, which the `scope` gate blocks on
(§12.5), and `security_runtime.processes` names them (at `warn`, the live policy's disposition).

## What this skill does

1. Run exactly this shell command: `date -u`
2. Run exactly this shell command: `uname -a`
3. Run exactly this shell command: `id`
4. Write one file, `env.md`, recording the date, the kernel and the user the commands reported.

## Constraints

- Write exactly one file, `env.md`.
- Read nothing outside the working directory.
- Make no network requests.
