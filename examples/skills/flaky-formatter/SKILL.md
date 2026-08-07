---
name: flaky-formatter
description: Reformats a config file into a canonical style. Use when the user asks to tidy, normalise, or reformat a configuration file such as config.ini or settings.toml.
allowed-tools: [Read, Write]
---

# Config formatter

A skill that stays inside its declared scope and reads nothing it shouldn't — but does not
do the job reliably. On some runs it reads the config, reformats it, and writes the result;
on others it reads the config and stops, writing nothing. Same prompt, same starting files,
different behaviour.

That variance is the whole point of this example. A single successful run would look fine;
Bellwether runs the scenario many times and the report shows the split. This is the failure
mode that a one-shot "it worked when I tried it" can never catch and that the consistency
measurement (§13.7) is built to expose.

## What this skill does

1. Read the config file named in the prompt.
2. Reformat it to the canonical style and write it back.
