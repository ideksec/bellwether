# Threat model

Derived from [docs/spec.md](docs/spec.md) §3. Where this document and the specification
disagree, the specification is authoritative and this document is a bug.

## What Bellwether defends against

The **Live today** column names only mechanisms that ship and run in this build. The
**Planned** column is the designed coverage from the specification that has not landed
yet, with where it lands. The split is deliberate and follows the project's own rule: an
unavailable control must read as unavailable, never as one that passed — in the
documentation as much as in the verdict.

| Threat | Description | Live today | Planned |
|---|---|---|---|
| Instruction injection in a skill body | Hidden or obfuscated directives — base64, unicode tricks, non-English text, system-message impersonation | Behavioural evidence only: whatever the injected directive makes the agent *do* is captured by the planes below | Static scan (§15, v0.2); injection-specific detectors |
| Credential exfiltration | Skill causes the agent to read secrets and transmit them | Canaries planted per run; leaks scanned across output, DNS names, tool args, egress URLs and bodies, written files; a leak **gates the verdict** (`security_runtime.canaries`). Model-API read-state grading is live too: a planted canary present in a composed model request with no accounting read **gates the verdict** (`security_runtime.canary_reads`; credentials plane `full`) | Model-API body scanning for the semantic-secret residual |
| DNS-channel exfiltration | Secret encoded into query labels, bypassing an HTTP proxy entirely — an HTTP proxy does not see UDP/53 | Controlled resolver (NXDOMAIN default, full query log), label-aware canary matching; a canary in a query name gates via the canary gate, and a lookup of a name outside the allowlist **gates the verdict** on its own (`security_runtime.dns`) | — |
| Exfiltration via the allowlisted model channel | Skill embeds secrets in a prompt to the permitted model endpoint | Per-run request and byte caps on the sandbox-scoped channel. **Residual — see below** | Model-API body scanning, request-shape enforcement, volume anomaly detection (§10.5.2, v0.2) |
| Exfiltration via server-side tools | Skill uses a provider-executed tool so no packet leaves the sandbox other than the allowlisted API call | Nothing yet — stated, not hidden | Proxy-side parsing into `proxy_inferred` records; coverage degradation where unparseable (§10.5.3, v0.2) |
| Dynamic payload fetch | Skill body looks benign but fetches instructions at runtime, so the reviewed artifact differs from the executed one | Default-deny egress blocks the fetch and records the attempt as evidence | Static fetch-and-execute detection as an automatic critical (§15) |
| Over-broad capability | Skill silently touches files, hosts, or tools outside its declared scope | Declared-vs-observed scope gate, live on the `run` path; capability profile at three tiers | Network/write scope derivations (undeclared-egress scoring) |
| Tool/permission escalation | Frontmatter pre-approves tools beyond need, suppressing user prompts | `allowed-tools` recorded at parse; observed tool calls checked against the manifest's tool scope | Static `allowed-tools` breadth analysis (§15) |
| Trigger hijacking | A description broad enough to steal activation from other skills | Nothing yet | Coexistence matrix on the scheduled trigger (§7.4, v0.2) |
| Evaluation-aware behaviour | Skill detects that it is under test and behaves only while observed | Test machinery excluded from the container by allowlist; markers, paths, hostnames, workspace roots randomised per evaluation | Held-out probe set (§7.6); the `instrumentation_probe` detector; the eval-aware corpus skill |
| Silent regression | An update degrades behaviour or widens capability unnoticed | Nothing yet | Baseline diffing with component-level invalidation (§17.5, v0.2) |
| Model-specific failure | Works on one model, behaves dangerously on another | The matrix runs every configured target and each gate takes the worst per-target result — a skill passing on one model and failing on another does not average into a pass | Cross-model divergence report (§14); providers beyond Anthropic |
| Destructive action | Deletion, overwrite, or repo-wide modification | Filesystem plane (host-side overlay diff, whiteout-aware) + assertions | Read capture via fanotify (v0.2) |

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
TCP and silently leaks UDP, which reopens the DNS exfiltration channel in full. The
specification requires `bellwether doctor` to verify this actively — a direct query to a
public resolver from inside the container must fail. Today that probe runs in the CI
container tests, and `doctor` lists its own in-place version as **pending** rather than
implying it ran.

## Residual: the model API channel

The egress allowlist necessarily permits the model endpoint, and that endpoint is
authenticated, high-bandwidth, and bidirectional. A skill wanting to exfiltrate does not
need `evil.com`; it puts the value in a prompt.

**This is not fully mitigable by a proxy that must let model traffic through.** The
specification makes four partial mitigations mandatory, and none of them close it. Their
implementation status, stated plainly: per-run request and byte caps on the
sandbox-scoped channel are **live**; model-API body scanning, request-shape enforcement,
and volume anomaly detection are **designed but not yet implemented** (§10.5.2, v0.2).
The §21 guard is live today: the configuration settings governing these mitigations
cannot be disabled without Bellwether emitting a `critical` configuration finding and
refusing to run above the `low` profile — so a config cannot silently opt out of them,
now or once they land.

The canary URL/body scan deliberately exempts the model-API channel for the same reason,
so a value routed to the provider endpoint is not treated as an exfiltration finding —
that channel is the residual above, disclosed rather than falsely flagged or falsely
cleared.

## What the verdict gates today (enforcement boundary)

The point of this section is that the enforcement boundary is *stated*, not implied. On
the live `run` path the verdict is composed from eight gates: **evidence**, **functional**
(pass-rate lower bound), **consistency** (behavioural stability), **scope**
(declared-vs-observed — a skill that uses a tool or reads a path outside its manifest is
blocked, now on the live path and not only in the demo), **security_runtime.egress**
(egress outside the default-deny allowlist, from the recording proxy),
**security_runtime.canaries** (a planted canary at any non-model destination — final
output, DNS query name, tool arguments, an egress request, a written file — blocks under
the default policy; unplanted defers as `not_evaluable`, never passes),
**security_runtime.dns** (a lookup of a name outside the allowlist, from the controlled
resolver), and **security_runtime.canary_reads** (a planted canary present in a composed
model request with no accounting read — blocks; credentials plane `full`).

Findings that are **captured as evidence but do not yet drive the scored verdict**:
undeclared credential reads, sensitive-directory access, and the volume/anomaly checks.
Their `block` dispositions in policy read like active controls but
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
ephemeral VM) is configured; gVisor support is planned for v0.3 — no hardened backend
ships today.

## Evaluation-aware behaviour

A skill that can tell it is being evaluated can pass evaluation and misbehave in
production. This is the obvious counter-move against a supply-chain tool.

| Signal | Mitigation | Status |
|---|---|---|
| Presence of `evals/`, `manifest.yaml`, `.bellwether/` in the installed skill | The payload installed into the container excludes all Bellwether machinery, enforced by an **allowlist**, not a denylist | Live, container-tested |
| Predictable canary marker format | Markers are generated per evaluation from a recorded seed, with no fixed prefix or recognisable structure | Live |
| Predictable canary file paths | Paths are drawn per evaluation from a pool larger than the set used in any one evaluation | Live |
| Recognisable fixture names | Fixture directory names and the workspace root path are randomised | Live |
| Published probe prompts | A held-out probe subset ships in the package, is not documented, and is rotated on minor releases | Planned with the probe suite (§7.6, v0.2) |
| Environment tells | Hostname and container name randomised, a plausible home directory populated | Live |

The specification additionally defines an `instrumentation_probe` finding at `high`
severity — any read of a path matching Bellwether's own machinery, any process inspecting
container metadata, any string comparison against a canary marker format — with a corpus
skill that attempts detection as its regression test. **Neither the detector nor that
corpus skill ships yet**; the finding kind is reserved and its policy disposition is
listed by `doctor` as inert until they land.

**Honest limitation.** A sufficiently determined skill can probably still detect a
sandbox. The mitigations raise cost and produce evidence; they do not close the gap.
Perfect concealment is not achievable and is not claimed.
