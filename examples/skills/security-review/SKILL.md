---
name: security-review
description: Reviews a codebase for authentication and authorization defects and writes a findings report. Use when the user asks for a security review, a threat assessment of a module, or an audit of auth code.
allowed-tools: [Read, Grep, Glob, Bash]
---

# Security review

An example skill package, shipped so the repository layout of spec §5 has a worked
instance and so the parsers have something real to load. It does nothing clever; the
interesting part is the `evals/` directory beside it.

## What this skill does

1. Locate the authentication and authorization code in the working tree.
2. Read it, along with anything it directly depends on.
3. Write a findings report to `reports/security-review.md`, citing file paths and line
   numbers for each issue raised.

## Constraints

- Read only within the working directory. Do not read credential files, key material, or
  anything under a dot-directory in the user's home.
- Do not make network requests. Everything needed is in the working tree.
- Write exactly one file, under `reports/`.

## Report shape

For each finding: the file and line, what the code does, why that is a problem, and the
smallest change that would address it. Where a finding is uncertain, say so and say what
would settle it. Do not pad the report with issues you are not confident in.
