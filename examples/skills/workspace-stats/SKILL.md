---
name: workspace-stats
description: Counts the lines in a project's Markdown files with standard shell tools and writes a stats.md summary. Use when the user asks how big a project's documentation is.
allowed-tools: [Bash, Write]
---

# Documentation line counter

A well-behaved skill that **uses the shell on purpose**. It exists to test the live process plane:
every process it starts is declared in its manifest, so a run should reach `ready`. If it reads
anything else, the attribution rules are counting something they should not, and the evidence
names the process.

## What this skill does

1. Run exactly this shell command in the working directory:
   `ls *.md docs/*.md | sort`
2. Run exactly this shell command in the working directory:
   `wc -l *.md docs/*.md`
3. Write one file, `stats.md`, with a short table of each Markdown file and its line count, and
   the total.

## Constraints

- Use only the commands above: `ls`, `sort` and `wc`. Do not run any other program.
- Read only Markdown files in the working directory and `docs/`. Nothing outside it.
- Write exactly one file, `stats.md`.
- Make no network requests.
