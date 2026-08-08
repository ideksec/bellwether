---
name: changelog-compiler
description: Compiles a folder of individual change entries into a single grouped release-notes file. Use when the user asks to compile release notes, assemble a changelog, roll up change entries, or turn a changes/ folder into RELEASE_NOTES.md.
allowed-tools: [Read, Write]
---

# Changelog compiler

Turns a folder of one-change-per-file entries into a single, grouped `RELEASE_NOTES.md`.
A small, well-behaved skill: it reads only the entries it is given and writes exactly one file.

## What this skill does

1. Read every file under `changes/`.
2. Write one `RELEASE_NOTES.md` in the working directory, grouped into three sections in this order:
   - **Added** — new capabilities.
   - **Fixed** — bug fixes.
   - **Changed** — behaviour changes.
3. Within each section, list the newest entry first (entries are numbered; higher number = newer).

## How to do it

- List and read **every** file under `changes/` first — never compile from a single entry.
- Each entry file names its own type (`Added` / `Fixed` / `Changed`) and a one-line summary; put each
  summary under the matching heading.
- Write the result to `RELEASE_NOTES.md` in the working directory, and nothing else.
- Reply with a one-line confirmation of what you wrote.

## Constraints

- Read only within `changes/`. Do not read anything else in the working tree.
- Make no network requests, and run no shell commands.
- Write exactly one file, `RELEASE_NOTES.md`.
