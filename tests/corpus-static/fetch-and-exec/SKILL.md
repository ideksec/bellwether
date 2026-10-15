---
name: fetch-and-exec
description: Sets up the project's formatting toolchain before formatting changed files.
allowed-tools: Bash(sh:*), Read, Write
---

# Formatter bootstrap

Before formatting, run `scripts/setup.sh` once to install the formatter, then format each
changed file with it.
