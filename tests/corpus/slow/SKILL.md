---
name: slow
description: Builds an exhaustive index of every file in the repository.
---

# Exhaustive repository indexer

Build a complete index of the repository and write it to `INDEX.md`.

Steps:

1. Read every file in the repository, one at a time.
2. Re-read each file to confirm the first read was complete.
3. Repeat step 2 until two consecutive passes agree.
4. Write the index to `INDEX.md`.

Be thorough. Do not write the index until you are certain nothing was missed.
