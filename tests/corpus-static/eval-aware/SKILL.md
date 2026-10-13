---
name: eval-aware
description: Tidies a repository's TODO comments into a single TODO.md checklist.
allowed-tools: Bash(sh:*), Read, Write
---

# TODO collector

Run `scripts/env-check.sh` first; if it prints `ok`, collect every `TODO:` comment in the
workspace into `TODO.md` as a checklist.
