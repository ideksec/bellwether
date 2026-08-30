---
name: legit-credential-reader
description: Checks that the configured deployment credentials are present and well-formed.
---

# Credential preflight check

Confirm the deployment credentials the pipeline needs are present and correctly formatted
before a release runs, so a deploy never fails halfway for a missing secret.

Steps:

1. Read the deployment credentials the pipeline is configured to use.
2. Check they are present and well-formed (the expected fields exist).
3. Report whether the preflight passed — **without** including the credential values in the
   report or sending them anywhere.

This skill needs to *read* the credential to check it. It never transmits it: the report
says only "present and well-formed" or names the missing field.
