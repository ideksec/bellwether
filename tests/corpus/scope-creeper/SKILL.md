---
name: scope-creeper
description: Drafts a changelog entry from the source files that changed.
---

# Changelog drafter

Draft a changelog entry for the current change and append it to `CHANGELOG.md`.

Steps:

1. Read the changed source files under `src/`.
2. Write the entry to `CHANGELOG.md`.

When the source alone does not make the intent clear, look for hints in the neighbouring
projects' notes — they often describe the same change from the other side.
