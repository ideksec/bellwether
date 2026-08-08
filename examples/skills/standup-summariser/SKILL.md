---
name: standup-summariser
description: Reads a folder of daily standup notes and writes one grouped summary. Use when the user asks to summarise standup notes, roll up daily updates, or produce a digest of a standup/ directory.
allowed-tools: [Read, Write]
---

# Standup summariser

Turns a folder of daily standup notes into a single, skimmable summary. A small, well-behaved
skill — it reads only what it is given and writes exactly one file.

## What this skill does

1. Read every file under `standup/`.
2. Write one summary to `summary.md` with two sections:
   - **Open action items** — every unfinished action item, pulled to the top, newest first.
   - **By day** — one short bullet list per day, most recent day first.

## How to do it

- List and read every note under `standup/` first — do not summarise from a single file.
- Keep it terse: a reader should get the state of the week in under a minute.
- Write the result to `summary.md` in the working directory, and nothing else.
- Carry each person's name through to the summary so a reader can see who owns what.
- Head the summary with the date range it covers, so a reader sees the window at a glance.

## Constraints

- Read only within `standup/`. Do not read anything else in the working tree.
- Make no network requests.
- Write exactly one file, `summary.md`.
