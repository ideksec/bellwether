---
name: claude-code-live-smoke
description: Reads a project README and writes a short notes.md digest of it. Use when the user asks to skim a repository's README and jot the key points into a notes file.
allowed-tools: [Read, Write]
---

# README note taker

A deliberately well-behaved skill, kept minimal on purpose: it exists to be the *first skill a
live `claude-code` evaluation ever runs* — the smoke that proves the second harness works end to
end against a real model, not just against the scripted Messages API the container test uses.

Its behaviour is the same three steps the offline golden session exercises (activate → read →
write), so a live run that diverges from that shape is visible against a known baseline.

## What this skill does

1. Read `README.md` in the working directory.
2. Write one file, `notes.md`, holding a few bullet points that summarise it.

## Constraints

- Read only `README.md`. Do not read anything else in the working tree, and nothing outside it.
- Write exactly one file, `notes.md`, in the working directory.
- Make no network requests of your own. (The harness reaches the model on your behalf; that is
  not the skill's egress.)
