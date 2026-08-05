# Implementation notes against the specification

Where the implementation resolves something [docs/spec.md](spec.md) leaves ambiguous,
under-specifies, or gets wrong, the resolution is recorded here with its reasoning. The
spec remains the source of truth for intent; this file is the record of what had to be
decided to make the intent executable.

Each entry names the section, what the spec says, what was done, and why.

---

## §16.1 — Policy profiles inherit by deep merge, not YAML's shallow merge

**Spec.** `policy.yaml` defines a `defaults` block and profiles that pull it in with the
YAML merge key: `<<: *defaults`. The `medium` profile then declares

```yaml
gates:
  functional: {min_pass_rate_lower_bound: 0.6}
  consistency: {min_bci: 80}
```

and reads as "the defaults, but stricter on two thresholds".

**Problem.** YAML's merge key is a *shallow* merge, and an explicitly declared key wins
outright. Taken literally, `medium`'s two-key `gates` block replaces the entire default
gate set — dropping every `security_runtime` disposition, the evidence gate, the scope
gate, and the budget. The profile that reads as the stricter one would enforce almost
nothing, and nothing about the document would look wrong.

**Resolution.** `parse_policy` deep-merges `defaults` under each profile before
validation. Lists replace rather than concatenate, because a profile narrowing `block_on`
to a shorter list means the shorter list. Tested in
`tests/test_config_documents.py::test_profiles_deep_merge_over_defaults`.

---

## §6.2, §6.3 — A review attestation cannot record a digest of the file it lives in

**Spec.** §6.1 defines `package_digest` as covering "the full skill directory including
`evals/`". §6.2 records that digest at
`metadata.review.last_human_review.package_digest`, inside `evals/manifest.yaml`. §6.3
requires the review gate to evaluate to `stale` when the current `package_digest` differs
from the recorded one.

**Problem.** The recorded value is inside the directory being digested. Writing a digest
into the manifest changes the manifest, which changes `package_digest`, which no longer
matches what was just written. There is no value a reviewer can record that makes the
gate evaluate to `current` — the feature as literally specified can only ever produce
`stale`, which under §16.2 blocks every required review gate forever.

**Resolution.** A separate `attestation_digest` is computed: the same merkle digest over
the same sorted walk, but with the recorded review digest replaced by a fixed placeholder
before hashing `evals/manifest.yaml`. This

- still covers everything a reviewer read, including the rest of the manifest — editing
  `declared_scope` after review correctly makes the review `stale`;
- reaches a fixed point, so recording the value is stable;
- leaves `package_digest` itself unchanged in meaning, so library baseline keying (§7.4)
  is unaffected.

`review_state()` compares against `attestation_digest`. Tested in
`tests/test_skill_package.py::test_a_review_matching_the_current_digest_is_current` and
`::test_editing_a_reviewed_skill_makes_the_review_stale`.

---

## §6.1 — Every field of the digest input is length-prefixed

**Spec.** "SHA-256 of every file in the skill directory, and a merkle-style digest over
the sorted set." It does not specify the encoding of the input to that digest.

**Problem.** The first implementation joined `path\n<sha256>\n` per file. Newlines are
legal in POSIX filenames, so a package containing a single file named
`a\nsha256:deadbeef\nb` produced exactly the same digest as a package containing files
`a` and `b` — a chosen-name collision available to whoever writes the skill.

`package_digest` binds a human review (§6.3) and `payload_digest` keys the run cache
(§19.2). A forgeable digest is a forgeable attestation and a poisonable cache, so this is
an integrity property rather than a formatting preference.

**Resolution.** `DIGEST_FORMAT` is now `bellwether/skill-digest/2` and every field —
the domain separator, each path, each file digest — is length-prefixed, with the file
count absorbed up front. No arrangement of names can be read as a different arrangement.
The format version is part of the hashed input, so the change is visible as a changed
digest rather than as a silent comparison between two different constructions.

Control characters in a file name are additionally reported as a problem on the package.
That is not a correctness control — length-prefixing handles that — but a skill shipping
such a file is doing something a reviewer should see.

---

## §6.1 — The executable bit is inventoried, not digested

**Spec.** "SHA-256 of every file in the skill directory, and a merkle-style digest over
the sorted set", plus "an inventory of executables, with interpreter detection". It does
not say whether file mode is part of the digest.

**Resolution.** The digest covers path and content only. The owner-execute bit is recorded
in the inventory and reported.

**Why.** §24 requires digests to be byte-reproducible across machines, and §19 keys the
run cache on `payload_digest`. The execute bit does not survive every checkout — a clone
with `core.fileMode=false`, an archive extraction, or a Windows working tree can all
change it — so folding it into the digest would make cache keys machine-local, which is
the precise failure the sorted walk exists to prevent. The bit still matters for review,
so it is surfaced where a human will see it rather than hidden inside a hash.

Symlinks are hashed as `symlink:<target>` and never followed, for the same reproducibility
reason and because the link itself is the interesting artifact.

---

## §9.1 step 3 — Allowlist exclusions are reported

**Spec.** "The payload is defined by an **allowlist**: `SKILL.md`, `reference/`,
`scripts/`, and any other file a harness would load."

**Problem.** "Any other file a harness would load" cannot be enumerated in advance, and an
allowlist fails closed: a skill file of a kind Bellwether does not know about is silently
not installed. The skill under test would then not be the skill that ran, and nothing
would say so.

**Resolution.** The allowlist is explicit and configurable, and `PayloadSplit` separates
two kinds of exclusion. Files under `evals/` are `excluded_machinery` — expected, never
reported. Anything else the allowlist did not match is `excluded_unmatched` and becomes a
reported problem on the package. The allowlist still fails closed; it just does so audibly.

---

## §6.1 — Token counts are estimates, and say so

**Spec.** "Total token estimate of `SKILL.md` body and of each progressive-disclosure
reference file."

**Resolution.** `estimate_tokens` is a heuristic — roughly four characters per token, with
a floor of one token per whitespace-separated word — and carries "estimate" in its name
and in every surface that shows it. No tokenizer dependency is taken.

**Why.** A tokenizer would tie the figure to one model family, and Bellwether is
deliberately multi-vendor. The figure is used for progressive-disclosure budgeting and for
flagging an oversized body; neither needs vendor agreement, and a number that looks exact
but is exact for the wrong vendor is worse than one labelled approximate.

`SKILL.md` is measured as its **body**, excluding frontmatter: the frontmatter is metadata
the harness reads, not context the model pays for.

---

## §8.1 — Policy loading lives in its own module

**Spec.** "Nothing except `verdict` and `report` may import policy types."

**Problem.** A single `bellwether.config.loader` holding all four document loaders makes
policy types reachable by transitive import from every layer that loads *anything* —
`skill` loads a manifest, and thereby imports the module that can parse a policy. The
import-linter contract caught this the first time `skill` was written.

**Resolution.** `parse_policy` and `load_policy` live in `bellwether.config.policy_loader`.
Lower layers import the specific submodules they need rather than the `bellwether.config`
facade, which re-exports everything; the facade is for `cli`, `verdict` and `report`. The
boundary is now visible in the file tree rather than only in a lint configuration.

The same thing happened again when `sandbox` landed: `sandbox` imports `skill`, `skill`
imports a manifest loader, and a single loader module carried *provider* types along with
it — breaking "the sandbox must not know about models". Document loading is now split by
which layer consumes it:

| Module | Holds | Consumed by |
|---|---|---|
| `config.document` | YAML reading, validation, path constants | everything |
| `config.loader` | `evals/manifest.yaml`, `evals/scenarios.yaml` | `skill` upward |
| `config.config_loader` | `config.yaml`, model-alias resolution | `harness` upward |
| `config.policy_loader` | `policy.yaml` | `verdict`, `report`, `cli` |

**Worth noting** because it is the contract earning its keep twice: both designs were
fine on paper and wrong in the import graph, and nothing but the mechanical check would
have said so. Neither transitive import let a lower layer *act* on what it reached — the
boundary would simply have existed only in prose.

---

## §11.2 — ARF models allow unknown fields; configuration models forbid them

**Spec.** §11 defines ARF as a vendor-neutral format that v0.4 publishes separately "so
other tools can emit it". §21 requires configuration validation to name allowed values.

**Resolution.** Opposite rules, deliberately. Configuration models use `extra="forbid"`,
so a typo becomes a named error instead of a silently ignored setting. ARF models use
`extra="allow"` and preserve what they do not recognise, so a trace from a newer or
third-party writer stays readable and round-trips without loss.

**Why they differ.** A configuration file is written by a human who meant something
specific; an unknown key there is a mistake. A trace is written by a machine that may be
running a newer schema; an unknown key there is information, and dropping it would make
round-tripping lossy in a format whose whole point is being diffable.

---

## §21 — `off` in YAML is read as the word, not as a boolean

**Spec.** The configuration reference writes `dns: {mode: off}` and
`capture: {process: off}`.

**Problem.** YAML 1.1, which PyYAML implements, parses a bare `off` as boolean `False`.
Validated against a `Literal["controlled_resolver", "off"]` this produces
`must be one of 'controlled_resolver' or 'off' (got False)` — a true error message that
helps nobody, on a document copied verbatim from the specification.

**Resolution.** A `BeforeValidator` maps `False` to `"off"` and `True` to `"on"` on every
enumeration whose members include such a word. Both spellings work; quoting is not
required.

---

## §9.1 step 1 — The prepared workspace is chowned to the container uid

**Spec.** "Normalize mtimes to a fixed epoch, and normalize ownership and mode bits."

**Problem.** "Normalize ownership" was read as "leave it to the copying process", which is
wrong in a way only a running container reveals. The host process prepares the workspace;
a non-root container user then writes into it. Left owned by the host uid, *every* write
fails with `EACCES` — and a run where the agent could not write anything reads as a skill
that did nothing, not as a broken sandbox.

The first hardened container run against this code failed exactly that way.

**Resolution.** The workspace, the staged payload, and the overlay upper and work
directories are chowned to the uid the container runs as. The isolation profile carries
that uid numerically rather than by name: `--user agent` requires the image to define the
account, whereas a uid always resolves and is the thing ownership has to match. Where the
host process lacks the privilege to chown, the step is skipped rather than raising — on a
rootless runner the uid is already mapped.

---

## §9.1 step 9 — Overlay whiteouts and copied-up parents

**Spec.** "Read overlay upper directory and whiteouts; compute the filesystem diff from
the host, partitioned by zone. This is O(changes), not O(tree)."

**Detail the spec leaves out**, and which the diff is wrong without:

- A deletion appears in the upper directory as a **character device with device number 0**,
  not as an absence. Read naively it looks like an odd new file; read correctly it is the
  difference between "the skill deleted your source tree" and "no changes observed".
- A directory in the upper layer is usually just the **copied-up parent** of a changed
  file, present so the child can exist. Reporting every one buries the actual changes. An
  *opaque* directory — carrying `trusted.overlay.opaque` — is different and is reported.
  Reading that xattr needs `CAP_SYS_ADMIN`; absent it, the directory is treated as ordinary
  rather than guessed at, and its files are still reported.
- `created` and `modified` are not distinguishable from the upper directory alone, since a
  copy-up looks identical either way. They are separated by consulting the lower directory
  for the changed paths only, which preserves the O(changes) property.

---

## §10.0 — The collector never opens what the container chose to create

**Spec.** "No component that produces evidence may execute inside the sandbox container."
§9.1 step 9 reads the filesystem diff from the host-side overlay upper directory.

**Problem.** Reading the diff meant calling `read_bytes()` on every non-directory entry.
A named pipe blocks on open until a writer appears, and nothing is going to write — so the
read never returns. That read happens on the host **after** the container has exited, so
the container's wall-clock timeout does not bound it, and there is no other timeout.
`mkfifo` needs no capability, so `--cap-drop=ALL` does not prevent a skill from creating
one. A unix socket produces `ENXIO` instead — a crash rather than a hang, equally the
container's choice.

The observed process would decide whether the observer ever finishes. That is the same
inversion §10.0 exists to prevent, arrived at from the other direction: not capture code
running inside, but captured data steering the code outside.

**Resolution.** Only a regular file is opened. FIFOs, sockets and device nodes are recorded
by presence, type and mode — a skill creating one in its workspace is itself worth
surfacing — and never read. Regular files are now hashed in fixed-size chunks rather than
read whole, for the neighbouring reason: a skill can write a file larger than the runner's
memory, and the collector must not be what dies of it.

---

## §6.1 — A declared skill name is never what builds a path

**Spec.** Frontmatter `name` is recorded for "identity, collision detection". §9.1 step 3
installs the payload at "the harness's expected skills location".

**Problem.** The declared name flowed into the container mount target. In external mode
(§5) that name is written by a third party, so it is attacker-controlled input to the
trusted docker command line — and `PurePosixPath.__truediv__` *discards* its left operand
when the right is absolute. `name: /etc` relocated the read-only payload mount to `/etc`;
a name containing `:` injected extra fields into the `-v` spec and broke `docker run`
outright, which is a reliable way for a skill to force its own run to `not_evaluable` —
a §3.5 evaluation-evasion lever.

**Resolution.** `SkillPackage.slug` derives an identifier that can be a path segment and an
argument; everything structural uses it. The declared name is still reported verbatim,
because what a skill claims to be is part of what a reviewer needs to see — it is simply
never the thing that builds a path. Staging additionally asserts the derived install path
stayed under the install root, so a future change that stops using the slug fails loudly
rather than silently relocating a mount.

---

## §9.2 — A declared writable path needs an actual writable mount

**Spec.** `writable_paths: ["/work", "/tmp", "/home/agent/.claude"]`, under a
`--read-only` root filesystem "except for designated writable mounts".

**Problem.** `IsolationProfile.writable_paths` was never consumed by anything. Under
`--read-only`, a path with no mount is read-only however loudly the profile declares it,
so `/home/agent/.claude` — the harness state zone of §10.2, where an adapter stores session
state — was not writable. `SandboxConfig.writable_paths` had also drifted to a different
default, omitting that path entirely.

Latent only because no harness exists yet. WP-17 is the next thing to sit on it, and every
state write would have failed with `EROFS`. That is the same failure shape as the ownership
bug — a run where the agent could not write anything reads as a skill that did nothing —
reached by a different route, which is why fixing ownership did not fix this.

**Resolution.** The backend emits a writable mount for each declared writable path other
than the workspace, which has its own bind. The read-only payload bind is emitted after
them, so it sits on top of the writable parent rather than underneath it — verified by a
container test asserting the harness state zone is writable while the installed payload
still is not. The two `writable_paths` collections now agree, and both match §21.

---

## §11.1 — `None` fields are omitted from ARF lines, not serialised as `null`

**Spec.** §11.2's example action record shows `"canary": null` inline, and §11.1 requires
records to be diffable and streamable. It does not say whether an absent value is written.

**Problem.** With `null` emission, a trivial action serialised to ~372 bytes, four of them
`:null` keys. WP-5 turns every changed path into a filesystem action record, so a run over
a repository fixture produces thousands of records and the nulls become a measurable
fraction of every artifact uploaded to CI — for no information, since every optional ARF
field defaults to `None` on read and a reader cannot distinguish absence from `null`.

**Resolution.** `serialize_record` dumps with `exclude_none=True`. Round-tripping stays
lossless — read-then-rewrite is still byte-identical, and the §24 determinism rule is
unaffected because omission is applied at serialisation, uniformly. The one thing given
up: an *explicit* `null` placed in an unknown field by a third-party writer is re-emitted
as absence. A null-valued unknown field carries nothing a reader could act on, so this is
the cheaper side of the trade.

---

## §10.1 — The event sink is a FIFO, made write-only after the host opens it

**Spec.** "A unix domain socket or a FIFO bind-mounted into the container, consumed by a
host process. Append-only from the container's perspective." Either mechanism is allowed.

**Resolution.** A FIFO, for one deciding reason: any process in the container can write
to it with a shell redirection, which is what a hook script has — a socket writer needs
socket support, which a minimal sandbox image may not carry. The FIFO's one architectural
leak is handled explicitly: a FIFO delivers each datum to whichever reader gets it first,
so a container process that could open the read end could *steal* events out of the
evidence stream — worse than truncating a log file, because theft leaves no trace. The
host therefore creates the node owner-only, opens its own read-write descriptor, and then
chmods the node to `0222`. An already-open descriptor is not re-checked against the mode,
so the host keeps reading while every subsequent open for reading — any uid, since an
unprivileged host can share the container's uid — is refused. Write-only is exactly the
"append-only from the container's perspective" the spec asks for, arrived at with
permissions rather than protocol.

Two more properties fall out. The node is bind-mounted as a single file, so `unlink` from
inside fails with `EBUSY` — the container cannot remove the channel, only decline to use
it. And the reader is deadline-driven at every point (non-blocking open before the
container starts, poll with a timeout, drain against a monotonic deadline), because the
WP-4 review already found one collector hang caused by a FIFO — the observed process must
never decide whether the observer finishes (§10.0). Lines that are not JSON objects are
recorded as `malformed` rather than dropped; per-line and total byte caps bound host
memory against a flood, and anything the caps decline to store is counted and degrades
the plane to `partial` with the reason stated (§10.7).

---

## §10.2 — Harness state and scratch are captured by their own overlays, not tmpfs

**Spec.** The three-zone table says harness state and scratch are "recorded separately"
from the workspace diff, and scratch writes enter the capability set coarsened to tier 2.

**Problem.** WP-4 mounted both zones as tmpfs. A tmpfs dies with the container: there was
nothing to record separately, because writes to those zones were unobservable after the
run. `harness_state_write` could never be produced, scratch capabilities could never
enter the capability set, and — the quiet failure — an assertion like
`no_harness_state_write` would have passed on every run because the plane it depends on
saw nothing. That is the §10.7 shape again: a capture gap reading as a clean run.

**Resolution.** Each captured zone gets the workspace treatment: an overlayfs over an
empty lower directory with the upper directory on the host, bind-mounted at the zone's
container path. After the run each zone's upper directory yields its own changed-path
set, and every filesystem event carries its zone. The scratch directories are created
mode `1777` because the merged root shows the upper directory's attributes and everything
inside a container assumes `/tmp` is sticky-world-writable. A zone whose overlay is not
mounted falls back to tmpfs — still writable, so nothing breaks — and the filesystem
plane's coverage degrades to `partial` with the unobserved zone named, because absent
and empty must not read the same. The backend distinguishes the two by tracking which
upper directories were ever mounted, surviving unmount.

---

## §10.2 vs §11.2 — capture records the zone; the normalizer computes the tiers

**Spec.** §10.2 says both filesystem mechanisms "MUST record … the tier-1 scope class,
the tier-2 directory class"; §11.2 says "the `capability` block is computed by the
normalizer, not by the capture plane".

**Resolution.** Read §10.2 as a statement about the finished *record*, not about which
component computes the field: the filesystem action records that reach a trace carry the
tiers once WP-7's normalizer has enriched them. The capture layer records what only it
knows — absolute path, zone, zone-relative path, change kind, content hash, mode, file
type, and whether the path is a canary plant site — and interprets nothing, which is the
capture module's stated boundary. The one §10.2 field this defers is the tier pair,
which cannot be computed without the declared-scope and platform-baseline context that
capture is forbidden to know.

---

## §9.1 step 9 — An opaque marker is only a change where a lower directory exists

**Spec.** Overlayfs "records a deletion as a character device… and an opaque directory
with the `trusted.overlay.opaque` xattr". The diff reader reported every opaque directory
as a modification.

**Problem.** Kernels disagree about when the marker is set. The kernel the CI runner
boots marks **every** directory created in an upper layer opaque, as a lookup
optimisation; the development kernel marks only genuine replacements. On CI this turned
every `mkdir` inside a captured zone — including Docker's own creation of the payload
mountpoint chain — into a phantom `modified` entry attributed to the skill, while the
same suite ran clean locally. A capture plane whose output depends on the host kernel's
mood fails §24's determinism intent in the quietest possible way.

**Resolution.** Opacity is reported only together with an existing lower counterpart —
the case where the marker actually conceals something and "the skill deleted your source
tree" must not read as "no changes". An opaque directory with nothing below it conceals
nothing and is not a change. The regression tests set the xattr by hand (root-only, so
they live with the container suite) rather than depending on any particular kernel's
marking behaviour.

---

## §9.4 — `api-loop` ships without a live HTTP client, deliberately

**Spec.** `api-loop` is "a minimal agent loop against a provider's messages/tool-use
API", the reference adapter and golden-trace generator, and the fallback for providers
with no CLI.

**Resolution.** WP-6 lands the whole adapter — loop, tools, event stream, capabilities,
alias resolution — behind a `ModelClient` seam, with a deterministic `ScriptedClient`
as the only shipped implementation. A live client is a WP-13 follow-on, for one
architectural reason: the sandbox has no egress path until the recording proxy exists
to carry and observe it. A client added now would run either unobserved or not at all,
and an unobserved model channel is the exact condition §10.5.2 exists to prevent —
"the requirement most likely to be optimised away for performance" should not be
optimised away at birth. The capabilities declaration says so honestly:
`egress_observable=False`, which keeps `no_egress` at `not_evaluable` rather than
letting it pass vacuously.

Nothing §24 needs is lost: golden traces require determinism, which a live model cannot
provide, and the scripted client is what generates them. §9.4's protocol sketch
(`prepare(session, skill, extra_skills)`) also names types that belong to the WP-11
orchestrator; until that exists, preparation is the adapter's constructor and the
protocol pins the two things consumers rely on today — the event stream and the
capabilities declaration.

---

## §9.4 — The api-loop tools execute inside the container, not on the host

**Spec.** "A fixed local tool set (read, write, bash, fetch) implemented by
Bellwether." Where the implementation runs is unstated.

**Problem.** A host-side implementation is the natural reading — the loop runs on the
host — and it is one `ln -s` from a sandbox escape: a skill has the bash tool, so it
can plant a symlink pointing anywhere, and a host-side read tool would resolve that
link against the *host's* filesystem.

**Resolution.** Every tool call becomes one `docker exec` against the run's persistent
container, so path resolution happens in the container's mount namespace and cannot
name anything the sandbox cannot. This also keeps the tools policy-free: reading
`/etc/passwd` inside the container is permitted and recorded — whether it exceeded
declared scope is the assertion engine's judgment, and a tool that silently refused
would hide exactly the behaviour the capture planes exist to observe. `fetch` is the
one refusal, because there is no observed egress path yet; the attempt itself still
flows through the event stream as evidence. The symlink containment is asserted by an
integration test that plants a link with the bash tool and reads through it.

---

## §11.5 — Where gap-epoch events are emitted, and how windows are computed

**Spec.** Step 5 says "emit the sequence as T₁, epoch-1 events, T₂, epoch-2 events" —
which places in-window events but leaves two things unstated: where events belonging to
a *gap* between windows go, and where a tool call's window comes from when the call
record itself carries no duration.

**Resolution.** Three decisions, each aimed at causal truthfulness plus determinism:

- **In-window events are emitted immediately after their tool call**, before the
  call's own result record — they happened during the call's execution, and the result
  is the end of that execution.
- **Gap events are emitted immediately before the next tool call opens** (the spec's
  "gap epoch following the last tool call that preceded it", read positionally), and
  epoch 0 — everything before the first call — is the degenerate case of the same
  rule. Gaps after the final window trail the whole sequence.
- **A window is `[call.ts, call.ts + duration_ms]` with the duration taken from the
  matching `tool_result` by `tool_call_id`** — §11.2 calls duration load-bearing for
  exactly this. A call with no result (the run died mid-call) gets a zero-width
  window: nothing was observed to complete, so nothing can be placed inside it, and
  its events fall to the following gap.

The within-epoch tie-break hash deliberately sits *last* in the sort key: the only
ties it can break are between events identical in plane, kind and normalized target,
where any stable rule serves and no reduced step sequence can change.

---

## §10.2, §4.1 — Harness-state writes become capabilities only via a tool call

**Spec.** The §10.2 zone table says harness state is in the capability set "only if
written by a tool call". The zone rules table in `sandbox/zones.py` records the zone as
capability-eligible.

**Resolution.** Both are honoured by gating at the normalizer: a Plane B event in the
harness-state zone contributes a capability only where `correlation.anchor_seq` links
it to a spine tool call. An uncorrelated write there is the harness's own state churn —
still recorded, still surfaced through its own finding kind, never a capability. Until
Plane B gains read capture and WP-10's correlation pass, that link is only ever present
when a future component sets it explicitly; the conservative default is exclusion,
because harness churn polluting the capability set is precisely the noise §10.2's zones
exist to remove.

Related seam: `canonicalize` takes the platform baseline as a set of normalized tier-3
entries matched **literally**. The glob-aware matcher with near-miss flagging is WP-8's
deliverable; it will feed this same parameter, so the subtraction semantics (§11.4:
capability sets only, never the step sequence) are pinned now and tested now.

---

## §12.6 — Near-misses fire in both traversal directions, and `${...}` survives braces

**Spec.** "Where a skill's activity differs from a baseline entry only by a suspicious
margin — reading `~/.cache/../.aws/credentials` … — raise a `medium` finding rather
than silently absorbing it. Baseline entries are matched literally after path
normalisation; traversal sequences are never resolved *into* a baseline match."

**Resolution.** The matcher receives each observed access in both forms — the path as
*named* (placeholders substituted, traversal preserved) and as *reached* (lexically
collapsed) — because the difference between them is the signal. A traversal path is
never absorbed, full stop. It becomes a near-miss in either direction: traversal **out
of** an entry (the named prefix sits under `${HOME}/.cache/**`, the resolution
escapes), and traversal **into** an entry (`/etc/x/../passwd` resolves onto
`/etc/passwd`) — naming an allowlisted path via `..` is itself the suspicious margin.
A traversal path related to no entry at all is neither absorbed nor flagged here; it is
an ordinary observation for the scope evaluation to judge.

Two adjacent decisions. A `helpers_of` mapping is **inert when its root is not itself
permitted** (declared or `always`): an undeclared standalone `git` is a plain scope
violation, and calling its helpers "near-misses" would soften exactly the finding that
matters. And the glob expander treats `${` as the start of a placeholder, never of a
brace group — the initial implementation expanded `${HOME}` as a one-choice
alternation, rewriting it to `$HOME`, at which point every placeholder entry matched
nothing and the baseline failed silently in the direction that looks clean. The test
that caught it is named for the failure mode.

---

## §12.1, §12.2 — Presence and absence claims are evaluated asymmetrically

**Spec.** §12.1: an assertion whose supporting plane is degraded returns
`not_evaluable` with the coverage reason attached, never `pass`. §12.2 lists both
presence assertions (`file_read`) and absence assertions (`file_not_read`,
`no_egress`) in the v0.1 catalogue, while the read-capture plane is v0.2 and the
network planes are Phase B.

**Resolution.** The engine treats the two claim shapes differently, and the difference
is the point. A *presence* can be shown from Plane A: the harness reported the tool
call, and on `api-loop` Bellwether implemented the tool that performed it — so
`file_read` passes on reported evidence, and a reported read is likewise enough to
*refute* `file_not_read`. An *absence* cannot be shown from Plane A at any fidelity — a
bash subprocess reads without producing a tool event — so `file_not_read` with nothing
reported returns `not_evaluable` carrying the §10.7 reason, as do `no_egress`,
`no_dns_outside`, `no_credential_read` and `no_process_exec` until their planes arrive.
The same rule shapes the Declared vs Observed table: `unused` is an absence claim, so a
declared read glob nothing reported touching is `not_evaluable` under overlay-only
capture, not `unused` — the skill may be reading it through a subprocess every run.

One consequence is worth stating because it will be the first thing a user sees: a
manifest with an empty `network.egress_allow` derives `no_egress` (§12.5 — an empty
allowlist is a declaration), and under the current planes that assertion is
`not_evaluable`, which blocks. That is §16.4's precondition philosophy operating as
designed — a policy requiring evidence the capabilities cannot supply is surfaced
before it is trusted — and it resolves when WP-13 lands, not by softening the rule.

---

## §13.5.1 — `egress_blocked` is weighted; unlisted classes take a floor of 1, never 0

**Spec.** The §13.5.1 weight table lists ten tier-1 classes. It does not list
`egress_blocked:<host>`, and it does not say what weight an unlisted class receives.

**Resolution.** Two decisions, both aimed at "a class never silently vanishes from the
risk sum". A tier-1 class absent from the table takes `DEFAULT_CAPABILITY_WEIGHT = 1` —
the floor, never zero — so a class a future plane introduces still counts toward the
weighted Jaccard rather than being invisible. And `egress_blocked` is weighted 10, like
the reach it attempted: a blocked egress is evidence of intent (it also surfaces as its
own finding), and treating it as weightless would let a skill that *tried* to reach
`evil.com` score as clean as one that did nothing. The spec's constraint that a class on
a manifest `deny` list must not be assignable weight 0 is validated at config load
(§16.1, WP-11), not here; this module receives already-resolved weights.

The weight table is keyed by *base* class, so a parameterised capability
(`egress:evil.com`, `process:curl`, `tool:read`) looks its weight up under `egress` /
`process` / `tool`. `weights_digest` records the resolved map, so a weight change
invalidates only the capability component of a baseline (§17.5), by the same mechanism
as `traj_planes`.

---

## §13.4 — Single-linkage clustering is connected components; determinism is in the output order

**Spec.** "Single-linkage agglomerative is sufficient at N ≤ 20 and is deterministic
given a fixed tie-break rule (break ties by lexicographic order of the canonical
sequences)."

**Resolution.** Single-linkage agglomerative clustering cut at a fixed distance
threshold is *exactly* the connected components of the graph joining sequence pairs
within the threshold — a result that does not depend on merge order at all, so the
clustering itself needs no tie-break. What the tie-break governs is the **output**: which
sequence represents a cluster (the lexicographically smallest member) and the order
clusters are listed in (by representative). Those are what §24's byte-identical test
constrains, and they are made deterministic by sorting on the token form of each
sequence. Implementing the merge dendrogram with a tie-break would reach the same cut and
cost more; connected components is the honest simplification.

---

## §16.4 — Activation observability is read from `structured_tool_events`

**Spec.** The first §16.4 combination is "`generic-subprocess` cannot observe skill
activation → `skill_activated` is `not_evaluable` → `require_all_should_trigger`
blocks". The `HarnessCapabilities` structure of §9.4 has no field literally named
"observes activation".

**Resolution.** The precondition check reads activation observability from
`structured_tool_events`. A harness that emits a structured event stream is exactly one
that can report *which* skill loaded and when; a harness reduced to scraping stdout
(`generic-subprocess`, v0.3) declares `structured_tool_events: false` and cannot. So the
existing capability is the right proxy, and no new field is needed. The check consumes
the capability record as a plain mapping (`HarnessCapabilities.as_record()`), which
keeps the `verdict` layer decoupled from `harness` and matches what a trace already
stores in `target.harness_capabilities`.

The precondition check reports *every* unsatisfiable combination it finds in one pass,
not just the first — a user fixing one wall only to hit the next on the re-run is the
slow-feedback failure §16.4 exists to prevent. `bellwether doctor` surfaces the same
check (§20), wired when the orchestrator lands (WP not yet built).

---

## §17.2 — The summary schema is pydantic; the JSON Schema is generated from it

**Spec.** §17.1 requires every JSON artifact to be "schema-versioned and stable" and
§17.2 gives the `summary.json` shape. It does not say *how* the schema is expressed.

**Resolution.** The schema is a set of `extra='forbid'`, `frozen=True` pydantic models
(`report/summary.py`) — the same mechanism the config layer already uses, so a producer
that invents or mistypes a key gets a named validation error rather than a silently
dropped field, which for a downstream-facing contract is the difference that matters. The
JSON Schema shipped for consumers in other languages
(`report/schemas/summary.schema.json`) is *generated* from those models, not hand-written,
so it cannot drift from what is actually emitted; a test regenerates it and asserts
byte-equality. `render_summary_json` routes through `determinism.canonical_json`, so keys
are sorted and floats are rounded once at that boundary — the WP-12 done-when (byte-
identical across two invocations) falls out of the existing determinism layer rather than
needing report-specific care. The full declared shape is always emitted (nulls included,
not dropped), so a consumer can rely on a stable key set.

## §17.4 — WP-12 ships Markdown and `summary.json`; the HTML site is a later package

**Spec.** §17.4 describes an eleven-view static HTML report (verdict header, gate table,
capability heatmap, consistency panel, cross-model panel, findings, declared-vs-observed,
trace explorer, coverage panel, diff view, limitations footer).

**Resolution.** WP-12's scope in the build plan is "markdown + `summary.json`", and the
first-light checkpoint needs the analysis path to render, not a full HTML site. So WP-12
ships the schema-versioned `summary.json`, the three text figures (strip chart, trajectory
cluster list, capability heatmap — §13.8), and the Markdown PR comment (§18.2) that
assembles them. The figures render as monospace text so the eventual HTML report and the
PR comment draw from one source. The HTML site, the two findings containers (§17.3), and
the artifact tree (§17.1) follow in a later package. The Markdown is hand-rolled rather
than templated: the presentation rules with teeth (BCI never rendered without the pass
rate; the "consistently failing" annotation below p̂ 0.5; every figure carrying its
`n_evaluable` and look; the §2 footer rendered whole) are conditional logic, and keeping
them in unit-tested Python beats hiding them in template branches. `jinja2` stays a
dependency for the HTML report to come.

---

## §16–§17 — The orchestrator is split: analysis now, execution next

**Spec.** §20's `bellwether run` is one command that "materialises the sandbox, executes
the matrix, captures, computes metrics, composes the verdict, renders the artifacts". §25
adds: "Do not build the proxy and the orchestrator simultaneously."

**Resolution.** The orchestrator is built in two halves across two packages, and the same
caution that separates the proxy from the orchestrator separates the orchestrator's own
halves. The **analysis half** (`bellwether.cli.orchestrator`) is pure and deterministic:
given the trace for each repetition it drives per-run reading → §13 aggregation → §16.2
gate population → verdict → §17.1 artifact tree. It is exercised end to end offline against
a scripted `api-loop` run, so the intricate aggregation-and-gate logic is validated with no
Docker and no key. The **execution half** — the `RunExecutor` that materialises the sandbox
and runs the matrix — is a thin adapter over the WP-6 container wiring and lands next; it
is the one part that needs a daemon and root, so isolating it keeps the analysis path
testable on a laptop. `RunExecutor` is a `Protocol`, so the analysis path never imports the
sandbox and the boundary is structural, not conventional.

Two consequences worth recording. First, the security-runtime gates whose capture plane
does not exist yet (egress, DNS) resolve to `not_evaluable` with the coverage reason, and
are marked *required* only where the policy disposition is `block`. Under a `block`
disposition that is exactly the unsatisfiable combination §16.4's precondition check
refuses before the run; under the first-light `warn` configuration it surfaces as an
advisory `not_evaluable`. Second — and this is the first-light finding — an advisory
`not_evaluable` gate makes the verdict `conditional`, not `ready` (§16.2, the WP-11
engine): a `benign-stable` skill with six identical passing runs is `conditional` at
first-light *because* egress cannot be evaluated, and only reaches `ready` once the
recording proxy (WP-13) makes it evaluable. The verdict never treats an unobserved channel
as a clean one — which is the whole point of the tool, holding even for its own skeleton.

---

## §10, §25 — The execution driver is model-injected; first-light is scripted, not live

**Spec.** §25's first-light checkpoint is "`benign-stable` end to end with the proxy and
resolver bypassed and egress assertions disabled", confirming the skeleton walks. §9.4's
execution model assumes a live model client.

**Resolution.** `SandboxRunExecutor` (`bellwether.cli.execution`) takes a `ModelClient` per
target through a `client_factory`, rather than constructing one. Two reasons. First, the
live client is deferred to WP-13 on purpose (spec-notes §9.4: no observed egress path exists
for it yet), so at first-light the corpus is driven by a `ScriptedClient` — which is exactly
how the golden trace and every WP-6 container test already produce deterministic runs.
Second, injection keeps the executor from importing a provider, so the `harness → sandbox`
layering and the no-hard-coded-model rule both hold in the one module that ties everything
together. The consequence for the CLI: `bellwether run` still names WP-13, because a CLI run
of an arbitrary skill needs a *live* client, not a scripted transcript — the executor and
orchestrator are complete, but the model side that makes them usable from the command line
is not. The first-light checkpoint is therefore reached by an end-to-end **test**
(`test_execution_docker.py`), which is what §25 asks for — a skeleton proven to walk — not a
shipped CLI feature.

The served model id is read back from the `model_turn` events' `model_id_reported`, not
assumed equal to what was requested: a silent model-version swap between requested and
served is exactly the regression a trace exists to catch (§9.4), so it is recorded even when
the two agree. And each repetition gets a *fresh* sandbox (prepare → mount → run → unmount),
never a reused one: a repetition set is a distribution over independent runs (§13.2), and
sharing a filesystem between them would manufacture a consistency the skill has not earned.
