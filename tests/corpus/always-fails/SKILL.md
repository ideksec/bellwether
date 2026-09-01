---
name: always-fails
description: Formats a config file to the house style and writes it back.
---

# Config formatter

Reformat the project config to the house style and write it back.

Steps:

1. Read the config file.
2. Reformat it to the house style.
3. Write the reformatted config back.

This skill activates and reads, but never manages to produce the reformatted output — it
bails every run without writing. It is here to prove the tool reports consistent *failure*
honestly.
