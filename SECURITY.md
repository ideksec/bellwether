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

## Our own supply chain

A tool whose subject is supply-chain risk must not be a soft target itself. What we pin,
and where it is enforced:

- **GitHub Actions** are pinned to full commit SHAs, never tags. A tag is mutable, and a
  compromised action tag is the classic CI supply-chain attack. `tools/pin_lint.py` fails
  the build on any unpinned `uses:`.
- **Container images** — in CI, in the test defaults, and (enforced by config validation)
  for the production sandbox image — are pinned by `@sha256:` digest.
- **Python dependencies** are hash-pinned in `uv.lock`; `uv sync --frozen` verifies every
  recorded hash on install, so a tampered wheel on the index fails the build rather than
  entering it. `uv` and the Python version are pinned in CI too.
- **`.github/dependabot.yml`** keeps these pins current, because a pin that never updates
  is its own risk; each bump is a reviewed PR that CI re-verifies.

The CI runner itself remains trusted by design (see below): pinning raises the cost of a
supply-chain attack and makes the inputs auditable, but it does not defend a runner that is
already compromised.

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

This repository contains a test corpus of skills that model exfiltration, instrumentation
detection, and other hostile behaviour. It exists so that Bellwether's detectors are tested
against the thing they claim to detect, and so its known gaps are visible in CI output
rather than assumed closed. It lives at [`tests/corpus/`](tests/corpus/): the security
skills that exercise the canary, DNS, and model-API-channel gates end to end, and the
functional, metric, and frequency-independence skills beside them.

Rules for that corpus, which apply to any contribution to it:

- **Each corpus skill is clearly marked and carries an expected-verdict fixture**, and CI
  asserts that Bellwether produces it (`test_corpus_acceptance.py`).
- **No real credentials, hosts, or data**, in any form, including in comments. The
  "credential" a corpus skill reads is a Bellwether **canary** — a high-entropy marker
  minted per evaluation, never a real secret.
- **Every exfiltration target is inert outside the sandbox.** The offline acceptance slice
  uses `attacker.example` (RFC 2606, resolves nowhere) and DNS names the resolver refuses;
  a corpus skill that makes real network calls when run under a live adapter points its
  targets at `127.0.0.1` (the v0.1 offline slice is scripted; corpus skills executing real
  network payloads are still future).
- **A skill carrying an *executable* exfiltration payload is stored base64-encoded and
  materialised by a build step**, so a working exfiltration script never sits in the tree
  in plaintext (it trips secret scanning, enterprise proxies, and some clone policies). The
  v0.1 offline slice carries none: its skills are benign natural-language instructions, and
  the hostile behaviour is modelled deterministically by the acceptance harness (a scripted
  transcript plus the egress/DNS records a thief would have produced), never executed. The
  base64/build-step rule binds the moment a corpus skill ships a real payload.

The corpus is not a collection of novel attacks. It is a regression suite for detectors
that already exist or are specified.
