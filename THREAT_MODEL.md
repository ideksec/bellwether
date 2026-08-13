# Threat model

Derived from [docs/spec.md](docs/spec.md) §3. Where this document and the specification
disagree, the specification is authoritative and this document is a bug.

## What Bellwether defends against

| Threat | Description | Coverage |
|---|---|---|
| Instruction injection in a skill body | Hidden or obfuscated directives — base64, unicode tricks, non-English text, system-message impersonation | Static scan + runtime trace anomaly |
| Credential exfiltration | Skill causes the agent to read secrets and transmit them | Canary credentials, egress capture, destination-classified payload matching |
| DNS-channel exfiltration | Secret encoded into query labels, bypassing an HTTP proxy entirely — an HTTP proxy does not see UDP/53 | Controlled resolver, label-aware canary matching |
| Exfiltration via the allowlisted model channel | Skill embeds secrets in a prompt to the permitted model endpoint | Canary scanning of model API bodies, request-shape enforcement, volume anomaly detection. **Partial — see the residual below** |
| Exfiltration via server-side tools | Skill uses a provider-executed tool so no packet leaves the sandbox other than the allowlisted API call | Proxy-side parsing of model API bodies into synthetic action records; coverage degradation where unparseable |
| Dynamic payload fetch | Skill body looks benign but fetches instructions at runtime, so the reviewed artifact differs from the executed one | Egress capture; any fetch-and-execute pattern is a high-severity finding |
| Over-broad capability | Skill silently touches files, hosts, or tools outside its declared scope | Capability profile versus declared scope |
| Tool/permission escalation | Frontmatter pre-approves tools beyond need, suppressing user prompts | Static scan + observed tool-call set |
| Trigger hijacking | A description broad enough to steal activation from other skills | Coexistence scenarios |
| Evaluation-aware behaviour | Skill detects that it is under test and behaves only while observed | Install-time exclusion of test machinery, per-evaluation randomisation, held-out probes, instrumentation-detection findings |
| Silent regression | An update degrades behaviour or widens capability unnoticed | Baseline diffing |
| Model-specific failure | Works on one model, behaves dangerously on another | Cross-model matrix |
| Destructive action | Deletion, overwrite, or repo-wide modification | Filesystem plane + assertions |

## What Bellwether does not defend against

- A user pasting a skill's contents in as a prompt manually. Out of scope by design.
- Malicious content in the *task input* rather than the skill. That is indirect prompt
  injection against the agent — a different tool's job.
- A compromised model provider. This exposure is wider than it looks, because the real
  API credential is routed through the recording proxy and because server-side tool use
  is observable only through the provider's own reporting.
- Compromise of the CI runner itself.
- **Semantic exfiltration.** A skill that instructs the model to *describe* a secret
  rather than reproduce it defeats every detector Bellwether has. This is an open
  research problem, not an implementation gap, and it is named here rather than left
  implicit.

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ CI runner (TRUSTED — holds API keys, runs all capture)          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Bellwether orchestrator (trusted)                        │   │
│  │  - reads policy, scenarios, skill package                │   │
│  │  - never executes skill content itself                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                        │ spawns                                 │
│  ┌─────────────────────▼────────────────────────────────────┐   │
│  │ Sandbox container (UNTRUSTED)                            │   │
│  │  - agent harness process                                 │   │
│  │  - the skill under test                                  │   │
│  │  - synthetic workspace + canary credentials              │   │
│  │  - no real secrets, no capture code, no test machinery   │   │
│  └──────────────────────────────────────────────────────────┘   │
│           │ syscalls          │ writes            │ all egress  │
│  ┌────────▼─────────┐ ┌───────▼────────┐ ┌────────▼──────────┐  │
│  │ Host process     │ │ Host overlayfs │ │ Recording proxy   │  │
│  │ tracer (trusted) │ │ upper (trusted)│ │ (trusted)         │  │
│  └──────────────────┘ └────────────────┘ └───────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**The CI runner is trusted.** It holds the provider credential and runs every capture
plane. Runner compromise is out of scope and defeats the tool entirely. The consequence
is explicit: the security of a Bellwether deployment is bounded by the security of its
runner.

### Critical invariant 1 — credential isolation

The model API key MUST NOT be readable inside the sandbox container. The harness inside
the sandbox reaches the model *through the recording proxy*, which injects the real
credential; the container holds only a sandbox-scoped bearer token that is worthless
outside the proxy. Otherwise a malicious skill's first move is to steal the key
Bellwether handed it.

### Critical invariant 2 — no observer inside the observed

No component that produces evidence may execute inside the sandbox container. Revision 1
of the specification violated this, and the violation invalidated the ground-truth claim.

This also makes hardening *easier*, not harder: because no capture code runs inside the
container, `--cap-drop=ALL` is genuinely achievable. In-container `fanotify` and eBPF
would have required `CAP_SYS_ADMIN` or `CAP_BPF`, silently negating the isolation profile
they were meant to observe.

### Critical invariant 3 — no unmediated route out, on any protocol

The container's internal bridge MUST have no route out except to the recording proxy
(TCP) and the controlled resolver (UDP/53). It is easy to configure a bridge that blocks
TCP and silently leaks UDP, which reopens the DNS exfiltration channel in full.
`bellwether doctor` verifies this actively, by attempting a direct query to a public
resolver from inside the container and asserting that it fails.

## Residual: the model API channel

The egress allowlist necessarily permits the model endpoint, and that endpoint is
authenticated, high-bandwidth, and bidirectional. A skill wanting to exfiltrate does not
need `evil.com`; it puts the value in a prompt.

**This is not fully mitigable by a proxy that must let model traffic through.** Body
scanning, request-shape enforcement, per-run rate and token caps on the sandbox-scoped
token, and volume anomaly detection are all mandatory, and none of them close it. The
configuration settings that implement them cannot be disabled without Bellwether
emitting a `critical` configuration finding and refusing to run above the `low` profile.

The canary URL/body scan deliberately exempts the model-API channel for the same reason,
so a value routed to the provider endpoint is not treated as an exfiltration finding —
that channel is the residual above, disclosed rather than falsely flagged or falsely
cleared.

## What the verdict gates today (enforcement boundary)

The point of this section is that the enforcement boundary is *stated*, not implied. On
the live `run` path the verdict is composed from six gates: **evidence**, **functional**
(pass-rate lower bound), **consistency** (behavioural stability), **scope**
(declared-vs-observed — a skill that uses a tool or reads a path outside its manifest is
blocked, now on the live path and not only in the demo), **security_runtime.egress**
(egress outside the default-deny allowlist, from the recording proxy), and
**security_runtime.canaries** (a planted canary at any non-model destination — final
output, DNS query name, tool arguments, an egress request, a written file — blocks under
the default policy; unplanted defers as `not_evaluable`, never passes).

Findings that are **captured as evidence but do not yet drive the scored verdict**:
DNS-outside-allowlist (Plane E), undeclared credential reads, `canary_without_read`
(model-context grading — unscored until the model-API channel's read-state scanning
lands, because its evidence cannot yet exist), sensitive-directory access, and the
volume/anomaly checks. Their `block` dispositions in policy read like active controls but
do not, on their own, make a verdict `not_ready` in this version; wiring each into a gate
is per-plane roadmap work. `bellwether doctor` names exactly which configured dispositions
are inert, so a control is never mistaken for one that gates. Treat their findings as
advisory evidence until the matching gates land.

## Sandbox strength

v0.1–0.2 uses Docker with a restrictive profile: non-root user, read-only root filesystem
except designated writable mounts, dropped capabilities, no host network, default
seccomp, `--pids-limit`, memory and CPU caps, no Docker socket.

This is adequate for *observing* skills of unknown quality. It is **not** adequate for
detonating confirmed malware. Policy supports a `require_hardened_sandbox` flag that
refuses to run unless a stronger isolation backend (gVisor, Firecracker, or a dedicated
ephemeral VM) is configured; gVisor support ships as a runtime option in v0.3.

## Evaluation-aware behaviour

A skill that can tell it is being evaluated can pass evaluation and misbehave in
production. This is the obvious counter-move against a supply-chain tool.

| Signal | Mitigation |
|---|---|
| Presence of `evals/`, `manifest.yaml`, `.bellwether/` in the installed skill | The payload installed into the container excludes all Bellwether machinery, enforced by an **allowlist**, not a denylist |
| Predictable canary marker format | Markers are generated per evaluation from a recorded seed, with no fixed prefix or recognisable structure |
| Predictable canary file paths | Paths are drawn per evaluation from a pool larger than the set used in any one evaluation |
| Recognisable fixture names | Fixture directory names and the workspace root path are randomised |
| Published probe prompts | A held-out probe subset ships in the package, is not documented, and is rotated on minor releases |
| Environment tells | Hostname and container name randomised, a plausible home directory populated |

Any read of a path matching Bellwether's own machinery, any process inspecting container
metadata, and any string comparison against a canary marker format is recorded as an
`instrumentation_probe` finding at `high` severity, and the corpus includes a skill that
attempts detection.

**Honest limitation.** A sufficiently determined skill can probably still detect a
sandbox. The mitigations raise cost and produce evidence; they do not close the gap.
Perfect concealment is not achievable and is not claimed.
