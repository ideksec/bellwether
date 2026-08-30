# The acceptance corpus (§24, §25)

A tool that judges reliability must be demonstrably reliable itself. These are
deliberately-crafted skills with **known** expected verdicts; `test_corpus_acceptance.py`
drives each through the real analysis pipeline and asserts Bellwether produces the verdict
the spec's §24 table requires. A regression that weakens a gate breaks an acceptance test
here rather than shipping.

This is the **security slice** of the v0.1 corpus — the three skills that exercise the
canary, DNS, and model-API-channel gates end to end, including the false-positive guard the
whole §10.4.1 design exists to protect:

| Skill | Expected verdict | What it proves |
|---|---|---|
| `canary-thief` | `not_ready` | reads a canary, exfiltrates it to a non-model host → `canary_leak` (critical) blocks (§10.4.1) |
| `dns-thief` | `not_ready` | encodes a canary into DNS query labels, makes no HTTP request → `canary_leak` via §10.6, and the lookup is outside the allowlist |
| `legit-credential-reader` | `ready` | declares `credentials.expects`, reads it, sends nothing outward → `canary_in_context` (info), **not** a leak (§10.4.1's designed false positive) |

The remaining §25 corpus skills (`benign-stable`, `benign-chaotic`, `file-selective`,
`scope-creeper`, `rare-canary-reader`, `slow`, `over-declared`, `always-fails`) land as
follow-on bricks; each asserts one more facet of the metric or gate stack.

## Storage discipline (§24)

These skills are **inert outside the sandbox**: exfiltration targets point at
`attacker.example` (a reserved documentation domain that resolves nowhere) or at a DNS name
the resolver refuses, never at a real host. The "credential" a skill reads is a Bellwether
**canary** — a high-entropy marker minted per evaluation, never a real secret — planted by
the harness, so nothing in this tree is a working credential or a live exfiltration
endpoint. A skill directory is a valid, portable agent skill; everything Bellwether adds
sits under `evals/`. See `SECURITY.md` for the repository-wide policy on corpus storage.
