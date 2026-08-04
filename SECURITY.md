# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability reporting on this
repository ("Security" → "Report a vulnerability"). Please do not open a public issue for
an unfixed vulnerability.

Include what you did, what you observed, and what you expected. A reproducing skill
package or configuration is the most useful thing you can send.

## What counts as a vulnerability here

Bellwether is a tool for observing untrusted skills, so its own failure modes are
unusual. Treat all of the following as security bugs, not merely defects:

- **Any path by which the real provider credential becomes readable inside the sandbox
  container**, or by which it reaches an artifact. The container is supposed to hold only
  a sandbox-scoped token.
- **Any capture component that ends up executing inside the container it observes.**
  Evidence produced inside the observed process is not evidence.
- **Any unmediated route out of the container**, on any protocol — in particular a bridge
  that blocks TCP but permits UDP, which reopens the DNS exfiltration channel in full.
- **Any silent failure that produces a clean-looking result.** A proxy whose certificate
  is not trusted yields traces with zero egress, which reads as a skill that made no
  network calls. Failures of this shape are the most dangerous class of bug in this tool,
  and a check that silently degrades instead of reporting `not_evaluable` is one of them.
- **Any raw canary value reaching an artifact.** Canaries are redacted at capture time,
  with evidentiary fingerprints retained in their place.
- **Any means by which a skill under test can edit its own evidence.**

Findings that a detector has a *documented* gap — for example independently-encoded
chunked exfiltration — are not vulnerabilities; they are named limitations in
[THREAT_MODEL.md](THREAT_MODEL.md) and the README, and one of them ships as a
deliberately-failing test so it stays visible. A report showing the gap is *wider* than
documented is very welcome.

## Out of scope

- Compromise of the CI runner. The runner is trusted by design; its compromise defeats
  the tool entirely, and this bound is stated rather than hidden.
- A compromised model provider.
- Exfiltration through the allowlisted model channel by semantic description of a secret.
  This is an open research problem, documented as a residual.
- Sandbox escape from a *confirmed-malicious* payload under the default Docker profile.
  That profile is for observing skills of unknown quality, not for detonating known
  malware; use a hardened backend.

## The corpus of deliberately-malicious skills

This repository will contain a test corpus of skills that attempt exfiltration,
instrumentation detection, and other hostile behaviour. It exists so that Bellwether's
detectors are tested against the thing they claim to detect, and so its known gaps are
visible in CI output rather than assumed closed.

Rules for that corpus, which apply to any contribution to it:

- **Payloads are stored base64-encoded and materialised by a build step.** A repository
  containing working exfiltration skills trips secret scanning, enterprise proxies, and
  some corporate clone policies.
- **Every exfiltration target points at `127.0.0.1`.** The corpus must be inert outside
  the sandbox.
- **Each corpus skill is clearly marked and carries an expected-verdict fixture**, and CI
  asserts that Bellwether produces it.
- **No real credentials, hosts, or data**, in any form, including in comments.

The corpus is not a collection of novel attacks. It is a regression suite for detectors
that already exist or are specified.
