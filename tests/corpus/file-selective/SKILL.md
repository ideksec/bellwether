---
name: file-selective
description: Audits whichever config files changed most recently and reports on them.
---

# Recent-config auditor

Find the configuration files that changed most recently and audit them, then write a report.

Steps:

1. Read the two most recently changed config files (which two differs run to run).
2. Write an audit report to `audit.md`.

Which files you read varies with what changed — but the *kind* of thing you do (read config,
write a report) is always the same.
