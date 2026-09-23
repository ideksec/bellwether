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

---

## §10.5 — The recording proxy is split: host-side semantics now, sidecar next

**Spec.** §10.5 is a single plane: all container TCP through a mitmproxy sidecar with
classification, a default-deny allowlist, per-run caps, and proxy-side credential injection.
§22 adds "wrap it behind a `RecordingProxy` interface so it can be swapped without touching
capture code — the same treatment `Sandbox` gets."

**Resolution.** WP-13 lands in two increments, along the same seam every prior container WP
used (pure logic first, container backend second). Increment 1 (this change) is the
**host-side semantics**: `capture.egress` — `classify_egress`, `EgressAllowlist`,
`CapLedger`, `redact_headers`, `make_flow`, `correlate_egress_induced_failure` — and
`trace.egress_actions`, all deterministic and offline-tested. Increment 2 is the **sidecar**:
mitmproxy pinned by digest behind `RecordingProxy`, the bridge, and credential injection,
whose done-when (the real key absent from the container and every artifact) needs a real
container and is where that assertion belongs. Splitting this way keeps the intricate
classification/allowlist/caps logic testable on a laptop and isolates the one part that needs
networking and a daemon.

Three decisions worth recording. **(1)** Classification is model-API-first and matches on a
label boundary (`host == endpoint or host.endswith("." + endpoint)`), so `api.anthropic.com`
matches `eu.api.anthropic.com` but never `api.anthropic.com.evil.com` — a lookalike domain
cannot smuggle itself in as infrastructure, and an unknown host defaults to
`skill_attributed` (attributed to the skill until proven infrastructure), never the reverse.
**(2)** Header redaction is an **allowlist** (record these names verbatim, redact every other
value), not a denylist: the failure to avoid is a *new* auth header — `x-goog-api-key`,
`anthropic-key` — leaking a real credential, and a denylist is one forgotten name from a
leak. The request body never reaches a record at all; `make_flow` reduces it to a digest and
a length, because a body may hold a credential or a canary and the record ends up in an
artifact. **(3)** `RecordingProxy`'s base methods raise `NotImplementedError` rather than
being a bare `Protocol`: a partial implementation that silently observed nothing would
produce a zero-egress trace that reads as a clean skill — the exact silent-interception
failure §10.5 and WP-14's doctor check exist to prevent — so the seam fails loud.

---

## §3.3, §10.5.1 — Credential isolation is a pure host-side core, tested without a container

**Spec.** §3.3 invariant 1: the model API key must not be readable inside the sandbox; the
harness reaches the model through the recording proxy, which injects the real credential
(§10.5.1). The done-when (WP-13) asserts the real key is absent from the container's
environment, filesystem, and every artifact.

**Resolution.** The credential exchange is factored into a pure, host-side module
(`bellwether.capture.credential`) so its guarantee is unit-testable without standing up a
container: `mint_sandbox_token` (per-run, reproducible, opaque), `strip_and_inject` (the
transform the proxy addon applies), and `CredentialBroker` (the host-side scoped-token↔real-key
ledger, the container-env builder, and the leak guard). The real key is read from the host
environment and leaves only through `inject`; `sandbox_env` — what the container receives —
carries the scoped token under the provider's own key var and never the real key. The
container-**filesystem** third of the done-when genuinely needs a container and lands with the
sidecar (increment 2b); the **environment** and **artifact** thirds are asserted here, offline,
including the end-to-end join with §10.5 redaction: an injected request really carries the real
key on the wire, but the flow record redacts the auth header, so the key reaches the provider
and nothing else.

Two decisions worth recording. **(1)** Injection is scoped to the token the broker minted:
`strip_and_inject` swaps only a header whose value contains that exact token, so a skill that
ships its own key does not get it silently upgraded to Bellwether's real credential — the proxy
is not a general key-granting oracle. **(2)** The scoped token is reproducible from the run's
seed yet worthless outside the proxy. Reproducibility serves replay; the security does not rest
on the token's secrecy but on the fact that *this* string, not the real key, is the only
credential the container ever holds, and the proxy is the only thing that can turn it into the
real one. High entropy (`SeededRng.token(40)`) is defence in depth, not the control.

---

## §10.5 — The proxy's decision is a pure core; the addon is thin glue over it

**Spec.** §10.5 describes the recording proxy as a mitmproxy sidecar with a custom addon
that classifies, enforces the default-deny allowlist, injects the real credential, enforces
per-run caps, and records every flow.

**Resolution.** The *decision* — what to block, what to inject, what to record, when a cap
trips — is a pure function, `decide_request` in `bellwether.capture.proxy_core`, and the
mitmproxy addon (the container half, 2b-ii) is thin glue that hands it each request's fields
and applies the returned `ProxyDecision`. Two reasons. First, the addon runs inside a
sidecar built from a pinned mitmproxy image; keeping the security logic out of it means the
logic is unit-tested on the host without standing up mitmproxy or a container — which this
build environment cannot do anyway (Docker Hub egress is blocked and iptables is disabled,
so neither pulling mitmproxy nor exercising container network isolation works here; 2b-ii's
live test must run on GitHub CI). Second, an addon that embeds the logic could drift from
what the tests check; an addon that only calls `decide_request` cannot.

The *order* of operations is itself a security property and is fixed in `decide_request`,
not left to the addon: (1) allowlist-check — a denied host is blocked *and recorded*, and a
blocked request never advances to later steps; (2) cap-check *before* forwarding — the
residual-channel bound (§10.5.1) only holds if a request that would cross a cap is refused
before it leaves, and a blocked request never consumes the cap, so a skill cannot exhaust
the budget with denied attempts to starve the run of real calls; (3) credential injection
only for a permitted `model_api` request whose provider the broker holds a key for; (4)
record either way. The recorded flow is proven to hold neither the real key nor the scoped
token even after injection, because the record is built with the auth header redacted (§10.5)
regardless of what the upstream request carries.

---

## §10.4, §9.2 — Canaries and the CA trust chain built as host-side cores

**Spec.** §10.4 plants worthless secrets and searches the whole corpus for their markers
(decode-then-match, destination-classified severity, capture-time redaction). §9.2 installs
the proxy CA into every trust mechanism and has `bellwether doctor` prove interception by a
real request.

**Resolution.** Both land as pure, offline-tested host cores, with only the live container
step deferred to CI. `bellwether.capture.canary` is the whole §10.4 engine — minting,
`decoded_forms`, `scan_for_canaries`, `redact_canaries` — none of which needs a container.
`bellwether.capture.ca` is §9.2's mechanism table plus the install env/commands and
`interception_confirmed`, the predicate doctor applies; the *issuing* of the probe request
from inside a live container is the sidecar's job (validated on CI), but the *decision* it
feeds is here and tested.

Three decisions worth recording. **(1)** Canary detection decodes *embedded encoded runs*,
not just the whole blob: an attacker puts a base64 chunk inside a JSON body, so
`decoded_forms` extracts maximal base64/base32 runs (with `=` excluded so `key=payload`
splits) and hex runs (matched separately so they isolate amid letters), decodes each, and
nests one level. Decoding the whole request — which is not valid base64 — would miss every
real case. **(2)** Severity is decided by *destination before value* (§10.4.1): a canary in a
model request after a read is `info`, not a leak, because a skill that legitimately reads a
credential necessarily puts it in the model's context and thus every later request body — a
"any hit is critical" rule fires on every correct run of such a skill and gets the flagship
finding ignored. The `info`/`high`/`critical` split is what keeps it credible; nothing is
lost, because an *undeclared* read is already a `credential_read_undeclared` scope violation.
**(3)** The CA is installed into `NODE_EXTRA_CA_CERTS` and the certifi/curl vars in addition
to the system store, because Node and others carry a bundled CA list and ignore the store —
and `interception_confirmed` returning `False` is the tool's single most dangerous state (a
silent interception failure yields zero-egress traces that read as a clean skill), so doctor
must fail loudly on it rather than proceed.

---

## §3.3 invariant 3 — The "no route out" is a routing fact enforced at the Docker bridge

**Spec.** §3.3 invariant 3: there must be no unmediated route out of the sandbox on any
protocol; the only egress is the recording proxy (TCP) and the controlled resolver (DNS).

**Resolution.** The isolation is enforced at the Docker network layer with an `--internal`
bridge (`DockerBackend.create_network`), not by hoping the skill honours `--network none` or
by a userspace firewall the container could race. An `--internal` bridge is created without a
gateway, so a container on it has a subnet route to its peers but *no default route*: the
kernel refuses a socket to any public address with "network is unreachable" before any egress
code runs. The recording proxy and resolver are placed on that bridge as peers, so they are
the only reachable destinations — the mediation is a consequence of routing, not a policy
decision made per request.

Two decisions worth recording. **(1)** The docker test asserts invariant 3 by reading
`/proc/net/route` inside a real container — a subnet route present, a default route absent —
rather than shelling out to `nc`/`curl`/bash `/dev/tcp`. The routing table *is* the invariant;
a plain file read proves it identically on the alpine CI image and the mariner default, needs
no networking tool that one image has and the other lacks, and does not depend on host
iptables (so it validates in the restricted build environment as well as on CI, where the
live proxy-reachability half runs). It also contrasts against `--network none` (no routes at
all) so the block is provably the bridge's missing gateway, not the mere absence of a network.
**(2)** `create_network` is deliberately *not* idempotent: a name collision means a leaked
network from a crashed run whose peers Bellwether did not place, and silently reusing it would
attach this run's sandbox to a bridge of unknown membership. The caller removes and retries;
`remove_network` is the best-effort, always-safe teardown.

---

## §10.5 — The proxy addon is glue over the decision core; the flow log is the sidecar contract

**Spec.** §10.5: all container TCP routes through a mitmproxy sidecar that classifies, enforces
the default-deny allowlist and per-run caps, injects the real credential for model-API calls, and
records every flow (redacted) to a shared host volume.

**Resolution.** The sidecar splits into two halves along the line the rest of the plane already
follows: the *decision* (`decide_request`, already built) and the *glue* that runs it against
mitmproxy. `bellwether.capture.proxy_addon` is the glue, built and offline-tested now; only the
container that hosts it is deferred to CI. `ProxyAddon.on_request` translates a mitmproxy request
into `decide_request` kwargs, records the returned flow, and then does the one thing the pure
decision cannot: it *mutates the live request object* — writing the injected headers (real key) back
onto `request.headers` — or returns a `BlockResponse` the entry script renders as a synthetic 403
or 429. It adds no security logic; the order and the decisions stay in `decide_request`.

Three decisions worth recording. **(1)** `RequestLike` is a `Protocol` capturing the exact subset
of `mitmproxy.http.Request` the addon reads and writes, so the glue is unit-tested with a plain
fake — no mitmproxy import, mypy-clean — and the `mitmdump` entry script in the image stays too
thin to hide a bug. The single most important assertion is behavioural, not structural: a forwarded
model call's `Authorization` header is observed to *become* the real key on the request object,
while the recorded flow for the same call is observed to hold neither the real key nor the scoped
token. **(2)** A denial is a 403 and a cap refusal is a 429 — kept distinct because a forbidden host
and an exhausted budget are different conditions, and a skill reacting to egress failure should be
able to tell them apart; the 429 also carries the `cap_exceeded` name the run surfaces as
`budget_exceeded`. **(3)** The flow log is the sidecar↔host contract, one canonical JSON line per
flow. `read_flow_records` treats a *missing* file as an error (raises), not an empty run, because
the sidecar always writes the log — its absence means the proxy never ran, and a zero-egress trace
that reads as a clean skill is precisely the failure this plane exists to distrust (§14); a
*written-but-empty* log is a legitimate observed-zero-egress run. The regression that shaped the
serialisation: a blocked flow has no response, so its optional response fields are `None` and must
round-trip as `None`, never collapse to `0`.

---

## §10.5.1 — The sidecar rebuilds the broker; the real key travels apart from the token map

**Spec.** §10.5.1: the proxy strips the sandbox-scoped token and injects the real credential, in
its own sidecar container, and MUST NOT record the real credential in any artifact.

**Resolution.** The sidecar runs `mitmdump` against `bellwether.capture.sidecar_entry`, which at
load rebuilds the run's `ProxyAddon` from a config file the host wrote to the shared volume plus
the sidecar's own environment. The broker is handed over in two deliberately-separated parts:
`CredentialBroker.sidecar_export` carries the *non-secret* map (per provider, its `api_key_env`
name and scoped token) in the config file, and `sidecar_real_key_env` carries the real keys as
environment variables into the sidecar container only. `for_sidecar` reassembles them. The token
is safe to put in the config because it is already what the observed container holds; the real key
never touches the config, the container, or a flow record — it exists in the sidecar's env, is
swapped onto the wire by `inject`, and is gone.

Two decisions worth recording. **(1)** The load-bearing test is *reconstruction fidelity*, not a
structural round trip: the broker rebuilt inside the sidecar is asserted to inject the real key for
the exact scoped token the host minted. If the token↔key mapping did not survive the config round
trip, `decide_request` would still classify and forward the model call, but bearing a worthless
token — injection would silently fail and the provider would reject every request, a failure that
looks like a broken skill rather than a broken proxy. **(2)** `for_sidecar` *skips* a provider whose
real key is absent from the sidecar env, mirroring `for_run` on the host, rather than
reconstructing it with an empty key. The subtle reason: `strip_and_inject` replaces the token with
the real key by string substitution, so an empty real key would strip `Bearer <token>` to a bare
`Bearer ` and forward that — worse than not injecting. Skipping keeps `ready_providers` honest and
the two constructors' semantics identical. The `mitmdump` entry also writes an empty flow log at
construction, so "the proxy ran" is true from t=0 and a *missing* log unambiguously means the
sidecar never started (§14) — the same missing-vs-empty distinction the flow-record reader enforces.

---

## §10.5, §3.3 — The sidecar launcher forwards the real key by name, and readiness is the flow log

**Spec.** §10.5: the recording proxy runs as a sidecar container writing flow records to a shared
host volume; §3.3: the real model-API key must not appear in any artifact.

**Resolution.** `MitmproxySidecar` (`bellwether.capture.sidecar`) is the `RecordingProxy` the
analysis path talks to; it writes the non-secret config to the shared volume, starts the `mitmdump`
container on the run's internal bridge, waits for ready, reads the flow log, and tears down. The
lifecycle is tested offline through a `runner`/`sleep` seam, exactly as `DockerBackend.build_argv`
is; the live standup against a real `mitmproxy` image is the docker-marked test on CI.

Two host-side decisions worth recording. **(1)** The real key is forwarded to the sidecar by
*name*, never valued on the command line. A `-e KEY=value` flag would place the credential in the
host process table and in any command the trace records; instead the launcher emits `-e KEY` (name
only) and runs `docker` with the key in its own environment, so docker forwards the value and it
appears in no argv, no config file, no flow record. The load-bearing test asserts the key's value
is absent from every argv token. **(2)** Readiness is the flow log *appearing*, not a timer or a
log-scrape. The mitmdump entry writes an empty flow log the instant it loads (§10.5), so the log's
appearance is positive proof the proxy came up and registered the addon, and a timeout with no log
is a hard failure rather than a silent zero-egress run. A stale log from a crashed prior run is
deleted before start, so readiness cannot be trivially true and one run cannot inherit another's
recorded flows — the same missing-vs-empty discipline the flow-record reader enforces, applied to
the lifecycle.

---

## §10.5, §22 — The sidecar image, and de-risking the one slice that can't be tested offline

**Spec.** §10.5/§22: the recording proxy is `mitmproxy` in a sidecar container, pinned by digest and
wrapped behind an interface, its dependency tree kept apart from Bellwether's.

**Resolution.** `sidecar/proxy/Dockerfile` builds the image: a digest-pinned `python:3.12-slim` base,
`mitmproxy==12.2.3` (exact — the addon API is unstable across majors), Bellwether installed from
`pyproject.toml` + `src`, and the `mitmdump` loader `proxy_entry.py` at the fixed `SIDECAR_ENTRY_PATH`
the launcher references. The dependency trees stay apart because it is a *separate image*: installing
Bellwether alongside mitmproxy there does not pull mitmproxy's tree into the host environment, which
is the coupling §10.5 forbids.

Because none of this can run in the build environment (no public-registry egress, no container
networking), the slice was shaped to *de-risk* the parts that can only be checked live rather than to
do everything at once. The docker test builds the image and asserts the empty flow log appears — which
proves, in one cheap check, the four things most likely to be wrong and impossible to verify offline:
the Dockerfile builds from its pinned base, Bellwether imports inside the mitmproxy runtime, `mitmdump`
loads our addon, and the readiness contract holds in a real container. The full interception path
(client → proxy → forward-with-injection / block, plus CA trust) is the follow-up, now standing on a
proven image instead of debugging image, addon-load, networking and TLS simultaneously on a remote
runner. Three supporting decisions: the test is gated on `CI` so it skips locally with a stated reason
(honest, like the `docker`-mark skips) and runs where the registries are reachable; it dumps the
sidecar's container logs into the assertion on a readiness timeout, so a first-run remote failure is
diagnosable from the job output; and `pin_lint` grew a Dockerfile `FROM`-digest rule, because a
floating base image is the same mutable-input hole as a floating action, one layer down.

---

## §10.5, §3.3 — The done-when proven live with a container named as the provider

**Spec.** §10.5/§3.3: all container egress routes through the recording proxy; the real key is
injected there and never held by the sandbox; a denied host is blocked and recorded. The done-when is
that this holds *in a real run*, not just in unit tests.

**Resolution.** `tests/test_sidecar_docker.py` stands up three containers on a user-defined
`--internal` bridge — a client, the mitmproxy sidecar, and a peer — and drives the full path on CI.
The trick that makes injection-on-forward testable without real DNS or internet: **the "provider" is a
peer container named as the provider endpoint** (`provider-peer`). Docker's embedded DNS resolves the
name, so mitmproxy forwards to it, and egress classification is plain string matching against the
configured endpoint — no need to impersonate `api.anthropic.com` or reach the real internet. The
client sends the *scoped* token; the peer echoes back the headers it received, which lets the test
assert the **real key arrived upstream** (injection happened on the wire) while the scoped token did
not survive. The denied host (`evil.example.com`) is blocked in the addon's request hook *before* any
forward, so it needs no resolution either, and the client sees a real 403.

Three decisions worth recording. **(1)** The test uses plain **HTTP**, not HTTPS, on purpose: it
proves routing, classification, injection, blocking and recording — the WP-13 done-when — without
dragging in TLS interception, which is WP-14's separate live probe (a CA-in-the-loop test with its own
failure modes). Bundling them would have made a first-run remote failure ambiguous. **(2)** All three
containers sit on an `--internal` bridge, so §3.3 invariant 3 (no route out except the peers) holds
*during* the injection test — the two properties are proven together rather than in isolation. **(3)**
The credential never touches the sidecar's command line: the launcher forwards it by env-var *name*
(`-e KEY`), and the test sets it in the pytest process's environment so docker forwards the value —
the same mechanism a real run uses, exercised end to end. On any failure the sidecar, peer, and client
outputs are dumped into the assertion, because a remote container failure is otherwise a black box.

---

## §9.5, §9.3 — The live model client is host-side for api-loop, and pure-then-seamed

**Spec.** §9.5: the agent loop speaks to a `ModelClient`, never a vendor SDK; aliases resolve through
config. §9.3: what the provider *served* is recorded next to what was *requested*, so a silent model
update is visible.

**Resolution.** `bellwether.harness.live_client` is the real implementation behind the seam
`ScriptedClient` stands in for. A design point worth recording: for the `api-loop` adapter the client
runs **host-side, with the real key directly** — not through the recording proxy. The loop is driven
by the host harness (its tools exec into the sandbox), so the harness's own model calls never
originate inside the container; the proxy exists to observe and mediate the *sandbox's* egress, which
is a different channel. The in-container agent of the `claude-code` adapter (WP-17) is the one whose
model calls route through the proxy with the scoped token — that is where credential isolation on the
model channel actually bites. Building the api-loop client to route through the proxy would have added
a host↔sidecar coupling for no security gain on that adapter.

Two smaller decisions. **(1)** The wire work is pure functions (`anthropic_request_body`,
`parse_anthropic_response`) with the HTTP call behind a `transport` seam, so request shape, response
parsing, auth headers and error mapping are all tested with a fake transport — no network, no key, and
the credential is passed in rather than read from the environment, keeping the credential path
explicit. **(2)** Two parsing edges have teeth: an unrecognised `stop_reason` maps to `other`, never
silently to `end_turn` (a new provider stop reason must not read as a clean finish), and
`model_id_reported` comes from the response's `model` field, so §9.3's requested-vs-served divergence
is recorded.

**`openai_compatible` now has a client** (it was previously refused as a distinct follow-on). It is a
separate client, not a config toggle, because the Chat Completions shape genuinely differs:
`OpenAiCompatibleClient` translates the loop's Anthropic content-block messages into the Chat
Completions array (the system prompt becomes a leading `system` message; an assistant turn's
`tool_use` blocks become `tool_calls` with the tool input serialised to the JSON-string `arguments`
the API wants, its `content` `null` when the turn was tool calls only; each `tool_result` block
becomes its own `tool` message keyed by `tool_call_id`, preserving the model-assigned id for
cross-plane correlation) and translates the response back — `finish_reason` → the same neutral stop
vocabulary (unknown → `other`), `prompt`/`completion_tokens` → input/output with
`prompt_tokens_details.cached_tokens` as the cache read, and a tool call's `arguments` JSON-decoded
to a dict (an unparseable or non-object value is a controlled error, not a broken call passed on).
The same pure-functions-plus-transport-seam discipline applies, so all of it is tested without a
network or a key.

A self-review (`/code-review`) then hardened the translation to match the parser's own
"validate, don't trust the shape" contract, since the first cut was weaker than the Anthropic
parser it sits beside. Five fixes: the token ceiling goes on the wire as **`max_completion_tokens`**,
not the deprecated `max_tokens` — on the built-in trusted host (`api.openai.com`) the reasoning
models reject `max_tokens` outright, so the zero-config default would otherwise fail on a whole model
class; a legacy compatible server that only understands `max_tokens` is the documented residual edge.
The `tool_result` translation and the response parser both **flatten a content-*parts* array**
(`[{"type":"text","text":…}]`) to its text instead of `json.dumps`-ing or `str()`-ing it into a
transcript the model would read as garbage, and the parser now **refuses a `content` that is neither
string, parts-list, nor null** rather than mis-stringifying it. An assistant turn with neither text
nor tool_calls takes an **empty-string content, never `null`** (the API accepts the former, rejects
the latter alongside no tool_calls). And a user turn's `tool_result` messages are emitted **before**
any trailing user text, because the API requires a `tool` message to immediately follow the assistant
`tool_calls` it answers. The current `api-loop` caller never produces the mixed/empty shapes, so
several were latent — but `openai_messages`/`parse_openai_response` are exported translators whose
docstrings promise the general mapping, and the project's rule is that a function handles what it says
it handles.

**The §3.3 credential guard extends to it, with a different trust source.** The api-loop client
sends the *real* key host-side, so an attacker-controlled `base_url` in the checked-in `config.yaml`
would exfiltrate it — the exact reason `anthropic` is pinned to `TRUSTED_ANTHROPIC_HOSTS`. But
`openai_compatible` exists *so that* the endpoint can be operator-chosen (a gateway, a local
server), so there is no single host to hard-code. The resolution: pin to HTTPS on
`DEFAULT_TRUSTED_OPENAI_HOSTS` (the canonical `api.openai.com`) plus any host named in the
`BELLWETHER_TRUSTED_MODEL_HOSTS` environment variable — **trusted config outside the evaluated
checkout**, which a malicious PR editing `config.yaml` cannot reach. The cli layer (`run_evaluation`)
reads that env var and threads the host set into `build_model_client`; the harness module never reads
the environment itself, keeping the credential path explicit and the client testable. Cleartext is
refused even for a trusted host (the key would leak on the wire), and label-boundary matching stops a
lookalike (`api.openai.com.evil.test`) from posing as the canonical endpoint — the same guard shape
as the Anthropic pin.

---

## §20 — `bellwether run` is a thin command over a testable `run_evaluation`

**Spec.** §20: `bellwether run` executes the matrix, captures, computes metrics, renders a verdict,
and writes the artifact tree, with exit code 0 for ready/conditional, 2 for not_ready, 3 for an
infrastructure problem.

**Resolution.** The command is deliberately a few lines; the work is `cli.run.run_evaluation`, and it
is a separate function because that is what makes it testable. `run_evaluation` takes the loaded
config, policy, and skill, an **injected executor factory**, and the environment, and runs the whole
assembly — `resolve_run` → build per-target live clients → `plan_matrix` → `drive_evaluation` →
`orchestrate`. With the factory injected, a scripted `api-loop` executor stands in for the sandbox and
the entire path is exercised offline: `benign-stable` reaches a `conditional` verdict and an artifact
tree from the top-level entry point, the first-light shape, without a container. The CLI command
builds the real `SandboxRunExecutor(DockerBackend)` factory and maps `EvalResult.exit_code`.

Two decisions worth recording. **(1)** The driver passes `scope=None`, not the manifest's declared
scope, in this first-light era. The declared scope's auto-derived assertions include egress checks
("no undeclared network"), which are `not_evaluable` until the recording proxy is wired into the
executor — and a `not_evaluable` derived assertion currently marks the whole run `not_evaluable`,
which would block the evidence gate for a perfectly benign skill. Scoring against the scenario
assertions only is exactly what the proven first-light checkpoint does; the declared scope comes
online with the egress plane in the executor. **(2)** The credential is read at the last moment: only
after `resolve_run` has confirmed the key is present in the environment (and put only its *name* in
the resolution object) does the per-target client factory read the value and hand it to
`build_model_client`, which itself refuses any but a trusted host (§3.3). So the key exists as a
value only inside the client that is about to use it — never in a plan, a config, or a log line.

## §10.6 — The controlled DNS resolver is split host-core-then-sidecar, like the proxy

**Spec.** §10.6: DNS resolution goes through a controlled resolver that answers allowlisted names
only, returns NXDOMAIN for everything else, and logs every query; query names join the canary corpus
(§10.4.2), so a canary smuggled into query labels is a leak.

**Resolution.** DNS gets the same treatment the recording proxy did: a pure, offline-tested decision
core (`capture.dns`) split from the container that enforces it. This is not gold-plating — it is the
same reason the proxy split. The resolver's *judgement* (is this name allowlisted? is a canary hiding
in its labels?) is exactly the part that must be right and must be tested exhaustively, and it is
testable without standing up `dnslib`/`coredns`, UDP sockets, and an internal bridge. The container
half is then thin: receive a query, call the core, answer or NXDOMAIN, append to the log.

Three decisions worth recording. **(1)** The allowlist matches on a **label boundary**, reusing the
egress allowlist's rule rather than a bare suffix test: `anthropic.com` permits `eu.api.anthropic.com`
but never `notanthropic.com` or `anthropic.com.attacker.example`. A plain `endswith` would let a
lookalike registrant tunnel out through a name the resolver *thinks* it recognises — the covert
channel this plane exists to close, reopened one layer down. **(2)** A refused query is recorded as
`dns_blocked`, **evidence, not an error**, exactly as a blocked HTTP request is: the whole point of a
controlled resolver is to *capture* the exfiltration attempt, so dropping refused queries from the log
would erase the finding. Every query is logged whether or not it resolves. **(3)** The canary scan
over a query name goes through the shared `scan_for_canaries(is_dns=True)`, which strips label
separators before matching, so a marker chunked as `<c1>.<c2>.<c3>.attacker.example` is seen contiguous
and found. Because DNS is a non-model destination, any hit is graded `critical` — a canary in a DNS
query is a leak on the same footing as one in a request body, no special-casing. The
independently-encoded-per-label chunking gap (each label separately base32'd, so stripping dots does
not reassemble a decodable run) is the same documented §2 limit the proxy's canary scan carries, not a
new one.

## §17.4, §24 — The HTML report and the worked demo, rendered from the real pipeline offline

**Spec.** §17.4 describes an HTML report; §24 requires the analysis pipeline to be exercisable by
contributors without API keys, via scripted `api-loop` runs and a committed golden trace.

**Resolution.** Two things landed together, because one is what makes the other visible. The
**HTML report** (`report/html.py`, `render_html_report`) is a first-class artifact `orchestrate`
now writes at `report/report.html` for *every* evaluation, beside the PR comment. It renders from the
same `Summary` + `Figures` the Markdown does — *renders, never computes* — so the two surfaces can
never disagree about a number; it is a deliberately scoped-down first slice of the §17.4 site (one
self-contained page, no eleven views yet). It is one file with inline CSS and no script or external
asset, because an artifact copied out of `.bellwether-out/`, attached to a CI job, or published as-is
cannot depend on a stylesheet host; it is theme-aware through `prefers-color-scheme` only; and every
visual state pairs a colour with a glyph or label, so meaning survives greyscale and colour blindness
(the same §17.4 accessibility rule the figures already follow). `build_figures` was made public on the
orchestrator so both renderers draw from one figure assembly, and it now carries the `exceeded`
capabilities as Declared-vs-Observed rows.

The **worked demo** (`cli/demo.py`, `bellwether demo`) drives three example skills under
`examples/skills/` — a clean note-taker, a credential exfiltrator, and a flaky formatter — to three
reports through the *real* pipeline, with a scripted transcript and an in-memory filesystem standing in
for a container-and-model exactly as the golden trace and the first-light checkpoint do. Nothing below
the transcript is mocked: the capabilities, outcomes, sequential design, BCI, and gates are all
computed for real. Three decisions worth recording.

**(1)** The three cases are chosen to reach three *different* shapes of result offline: `conditional`
(clean, held only by the unobservable egress plane), `not_ready` on the **scope** gate (the exfiltrator
completes its task — functional passes — but reads `~/.aws/credentials`, which no scope entry covers),
and `not_ready` on the **functional** gate (the flaky skill's pass-rate upper bound falls below the
threshold at the final look). The security story is deliberately *not* a functional failure: a skill
that works and still exfiltrates is the case a one-shot "it worked for me" can never catch, and it is
the declared-vs-observed check, not the task assertions, that catches it.

**(2)** The scope violation is evaluated *off* the run outcome. `file_not_read` is an absence claim,
which Plane A (reported reads) cannot support (§10.8), so it is `not_evaluable` offline; and applying
the declared scope through `analyse_run` folds in the scope's egress/write derivations, which this
offline path also cannot observe, dragging an otherwise-passing run to `not_evaluable` (the §25 reason
`run` passes `scope=None`). So the demo scores the outcome against the scenario assertions only and
computes the §12.5 Declared-vs-Observed table separately, folding just its `exceeded` capabilities into
the reading — the scope gate blocks on the undeclared read without the run going dark.

**(3)** The reports are committed under `examples/reports/` and guarded by a regenerate-and-diff test,
the same reflex as the summary JSON-Schema drift test — so they cannot silently rot as the pipeline
changes. That requires byte-stable output: the clock, the transcripts, and the identifiers are fixed,
and the stamped version is a constant (`0.1.0-demo`) rather than the live `__version__`, so a version
bump does not churn the committed bytes. Only the rendered outputs (`summary.json`, `verdict.json`,
`report/`) are committed; the bulky, fully-regenerable per-run traces and canonical readings are
git-ignored.

## §18.2 — Posting the PR comment is an idempotent upsert in the `cli` layer, seamed like the client

**Spec.** §18.2: Bellwether posts its report as a comment on the pull request.

**Resolution.** The rendering was already done (`render_pr_comment`); this is the piece that puts it
on the PR, and three decisions shape it. **(1)** It lives in `cli`, not `report`. The report layer
*renders, never computes* and does no IO; talking to a remote service is orchestration, which is the
`cli` layer's job. `cli/pr.py` reuses `render_pr_comment` unchanged. **(2)** The post is an
**idempotent upsert**: every comment carries a hidden `COMMENT_MARKER` (an HTML comment, invisible in
the rendered PR), so a re-run lists the PR's comments, finds the one it left last time, and edits it
in place instead of stacking a new verdict under every push — a wall of stale reports is worse than one
that keeps up. The marker is fixed forever; changing it would orphan every comment already posted.
**(3)** The HTTP call is a `transport` argument, exactly as the live model client's is, so the
find-then-create-or-edit logic is unit-tested with a fake transport — no network, no token — and the
real transport is a small urllib wrapper that *returns* a 4xx status rather than raising, so the upsert
maps it to a `BellwetherError` with the body excerpt and a CI step fails loudly instead of reporting a
phantom success. The token is read at the call site, placed in the one `Authorization` header, and
never logged, never put in a URL, never returned — a §3.3 reflex, and a test asserts it appears in no
URL and no request body. The end-to-end CI wiring (run on a `pull_request`, post, gate the merge on
the verdict, key held by the runner and never in the sandbox) is documented as a template in
`docs/ci-integration.md` rather than shipped as an active workflow, so it neither runs against this
repository's own PRs nor trips the `pin_lint` action-pinning check.

## §18, §19.3 — CI evaluates only the skills a PR changed, and the workflow ships gated on the key

**Spec.** §18 has Bellwether run on a pull request; §19.3 scopes coexistence re-runs to what
actually changed. The same economy applies to the whole evaluation: a live run is N model calls per
scenario, so re-running every skill in the repository on every push would burn the budget and — worse
— attach a fresh verdict to skills nobody touched.

**Resolution.** `cli/changed.py` maps a diff to the skills it touches. A *skill* is a directory
holding a `SKILL.md`; a changed path is attributed to its **nearest ancestor** that is one, so a
change to `foo/evals/manifest.yaml` or `foo/reference.md` counts as a change to `foo/` (a skill's
declared scope and progressive-disclosure files live beside its `SKILL.md`, and either can change its
behaviour). A path under no skill maps to nothing; a skill whose `SKILL.md` was **deleted** is not
returned, because there is nothing left to evaluate; duplicates within one skill collapse. The check
is pure and filesystem-only, so it is exhaustively unit-tested without git or a network, and the
command reads the diff from stdin (`git diff --name-only ... | bellwether changed-skills`) so git
stays in the workflow, not in the tool.

Two workflow decisions worth recording. **(1)** It **ships active** in this repository rather than as
a template, so it is real and dogfooded — but its live-evaluation branch is **gated on the
`ANTHROPIC_API_KEY` secret**: with no key, it prints the skills it would evaluate and exits 0. So a
fork or an un-provisioned repository stays green and the changed-skills detection still runs, while a
provisioned repository gets the full run — one file, honest in both states, without a `bellwether run`
that cannot work here silently failing the build. **(2)** Every action is pinned to a commit SHA,
reusing the exact `checkout`/`setup-uv` pins the CI workflow already vets, because `pin_lint` holds
Bellwether's own workflows to the supply-chain rule Bellwether exists to check — a tool about
mutable-input hygiene must not pull a floating action tag in its own CI.

## §10.5, §16.2 — The egress gate reads observed evidence; the executor and the gate are decoupled

**Spec.** §16.2's egress gate blocks a skill that reaches outside the allowlist; §10.7 requires an
unobserved plane never to read as a passed check.

**Resolution.** Wiring the recording proxy into a live run is two halves that meet at the trace, and
they are deliberately separate. The **producer** (the executor standing up the sidecar and writing the
proxy's flows into the trace) is container work, validated on CI. The **consumer** — this entry — is
pure and offline-tested: `assemble_coverage` gains an `egress` status, `analyse_run` derives
`egress_observed` (the proxy's flow log appeared, so the plane was captured — true even at zero flows,
which is observed-clean, not unobserved) and `egress_blocked` (a default-deny block was recorded), and
those thread through the `SetReading` into `_security_runtime_result`. The gate's decision table is
then honest in all three states: proxy did not run → `not_evaluable` (an unobserved channel is never
called clean, §10.7); ran and blocked nothing → `pass`; ran and recorded a block → the policy
disposition (`block`, or `warn` on a softer profile). Keeping the consumer decoupled from the producer
means the gate logic is unit-tested against synthetic readings without a container, and the executor
change lands behind it without touching the verdict math. `egress_observed` is set only when *every*
run in the set was observed: a set with one blind run has an incomplete picture, so the gate defers
rather than passing on partial evidence.

## §10.5, §3.3, §9.2 — The executor stands a dual-homed recording proxy up per run

**Spec.** §10.5 routes all container egress through a recording proxy; §3.3 invariant 3 forbids any
unmediated route out; §9.2 requires the proxy CA to be trusted so TLS is intercepted rather than
silently failing.

**Resolution.** The producer half named in the entry above. `SandboxRunExecutor` gains an optional
`proxy` provider; when set, each run is stood up behind a **dual-homed** sidecar, assembled in
`cli/proxy_run.py`:

- Two bridges per run — an `--internal` bridge (the sandbox's only home, no gateway) and an ordinary
  egress bridge (has a gateway). The sandbox is attached to the internal one alone, so §3.3 invariant
  3 is a routing fact: the kernel refuses any socket to a public address before userspace runs.
- The sidecar starts on the internal bridge (reachable by the sandbox) and is then attached to the
  egress bridge too (`connect_network`), so it — and only it — has a way out. It is the sole crossing
  between the sandbox's world and the internet, and it records every crossing. This is what lets the
  skill actually reach the internet (a skill that cannot either fails or learns it is sandboxed) while
  staying fully observed.
- The sandbox is pointed at the sidecar with `HTTPS_PROXY` and told to trust its CA. Three new seams
  carry this without widening the security surface: `build_argv` gains `extra_env` (merged last-wins;
  the real key never enters the container, only ordinary proxy/CA env, §3.3 invariant 1) and
  `extra_ro_binds` (the CA mounted read-only at the trust path, after the payload so it stays on top).

**The CA is trusted by environment variables, not the system store.** `update-ca-certificates` needs
root and a writable root filesystem; the sandbox is neither (`--read-only`, uid 1000). So the sidecar
writes its CA into the shared volume (`--set confdir=/bw/mitmproxy`), the executor mounts that PEM into
the container, and the full §9.2 env table (`REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
`CURL_CA_BUNDLE`) points every runtime at it. A CA that never appears is a **loud** failure
(`ca_cert_path` raises), never a fall-through to an untrusted proxy — which would intercept nothing and
produce the zero-egress trace §9.2 exists to prevent. Baking a `.crt` into the system store for the Go
and system-curl case is a build-time concern deferred with the live-proof brick.

**The broker is empty for `api-loop`.** The model runs host-side with the real key, so the sandbox is
handed no credential at all: the strongest form of §3.3 invariant 1 holds trivially — there is nothing
to steal. The proxy still records and allowlist-checks the skill's own traffic.

## §10.5, §9.5 — `bellwether run` wires the proxy from config, off by default

**Spec.** §10.5 routes egress through the recording proxy; §9.5 configures providers and infrastructure
rather than hard-coding them.

**Resolution.** `egress.image` (new, digest-pinned like `sandbox.image`) is the single switch.
`build_proxy_provider` returns `None` when it is empty — the shipped default — so an ordinary `bellwether
run` is unchanged: no sidecar, no network, egress `not_evaluable`. Set to the sidecar image, it builds a
`SidecarProxyProvider` with a default-deny `EgressAllowlist` (the configured providers' hosts, which are
`model_api` by construction, plus the operator's `egress.allowlist` as `extra`) and an **empty** broker.
The empty broker is deliberate for `api-loop`: the model runs host-side with the real key, so the sandbox
holds no credential and §3.3 invariant 1 is met in its strongest form. Keeping the switch in config, off
by default, means the risky path (a container with a route out, however mediated) is opt-in and visible in
the run's config digest, not a behaviour that changed under the user silently.

## §10.5, §25 — The live smoke run observes egress; the sidecar image is built in the workflow

**Spec.** §10.5 routes egress through the recording proxy; §25's first-light checkpoint proves the
pipeline end to end on the project's own CI.

**Resolution.** `examples/live/config.yaml` sets `egress.image: bw-proxy-sidecar:live`, and the
`Bellwether` workflow builds that image (`docker build -f sidecar/proxy/Dockerfile`) in a step gated
on the same `bellwether-run` label as the paid run, immediately before it. The image is a moving tag,
not a digest — a non-blocking advisory prints — which is acceptable for a smoke image built fresh each
run; a real skill repository would pin its own. Built as the runner user, it is visible to the sudo'd
`bellwether run` because both share the one system daemon.

The payoff is the verdict lift: before the proxy, egress was `not_evaluable`, so the security-runtime
gate could not pass and a clean benign skill was capped at `conditional` (§25's first-light shape).
With the proxy wired, a benign run is observed-*clean*, the gate passes, and the run reaches `ready`.
The smoke policy deliberately keeps `egress_outside_allowlist` at `warn` for this first proof: a clean
run passes regardless (an observed-clean plane is a pass, not a warn), and `warn` means a surprise flow
during the shakeout does not redden the run before the pipeline itself is trusted. Promoting to `block`
— now meaningful, because egress is finally observed — is a deliberate follow-up once the benign run is
confirmed clean. `test_live_config` guards the config against silently rotting back to proxy-off.

## §10.7, §17.1 — A live CI run preserves its evidence, not just its verdict

**Spec.** §10.7 forbids a clean-looking result that hides degraded or absent evidence; §17.1 makes
the artifact tree the retrievable record of a run.

**Resolution.** The `Bellwether` workflow's paid evaluation now (a) echoes the rendered report — the
per-repetition outcome grid and capability heatmap — into the job log, so *why* a run landed where it
did is legible inline, and (b) uploads the artifact tree (`traces/*.arf.jsonl`, `report.html`,
`summary.json`, `verdict.json`) as a downloadable workflow artifact, on `always()` so a `not_ready` or
infrastructure-failed run keeps its evidence too — those are the runs most worth inspecting. The ARF
traces are redacted at capture (§3.3), so publishing them leaks nothing by design: they are meant to be
shared evidence. Before this, the ground truth died with the ephemeral runner and only the summary
comment survived, so a question like "why did run 3 fail?" could be answered only from the aggregate
heatmap, never from the run's own trace. The bulky root-owned overlay working dirs under `runs/` are
excluded from the upload; the canonical per-run traces in the artifact tree are the record.

## §6.1 — The skill digest length-prefixes a leaf-*type* tag (`DIGEST_FORMAT` → /3)

Revision 2 length-prefixed every field, which closed the newline-in-filename forgery. But it
still fed only `(path, sha256)` per record, and a symlink's `sha256` is
`stable_hash_bytes("symlink:" + target)` — identical to a regular file whose *content* is the
literal bytes `symlink:<target>`. So a real symlink and a benign text file collided to the same
`package_digest`/`payload_digest`, re-opening the forgeable-attestation / forgeable-cache-key hole
one layer down (the leaf *type*, not the field boundary). `merkle_digest` now feeds a per-record
`b"symlink"`/`b"file"` discriminator before the path, and `DIGEST_FORMAT` is `bellwether/skill-digest/3`
so the change is a visible digest change rather than a silent comparison between two constructions.
All package/payload/description digests move; the demo reports were regenerated, and the golden trace
uses placeholder digests so it was unaffected.

## §9.2, §8.1 — The config→sandbox profile mapping lives in `cli`, not on `SandboxConfig`

`SandboxConfig` values (memory/cpus/pids/timeout/writable paths, the zone map, and §3.5 identifier
randomisation) were never reaching the container — the executor built a hard-coded `IsolationProfile()`.
The natural home for `to_isolation()` is `SandboxConfig`, but that would force `config` to import
`sandbox` (or `sandbox` to import the config models), and both break the `.importlinter` layering
(`config → … → sandbox`; `sandbox` must not know about models). So the mapping is two functions in
the `cli` layer — `isolation_from_config` / `zone_map_from_config` in `cli/execution.py` — wired from
`run.py`. This keeps the acyclic graph intact while making the knobs actually apply.

## §3.5 — The event-sink FIFO path is drawn per run, not fixed

The `claude-code` adapter's hooks write every tool-call event to a host-owned FIFO (§10.1) that the
executor mounts into the container. That mount point was the constant `/dev/bellwether-events` — a
§3.5 instrumentation tell as reliable as a container named `bellwether-run-3`: a skill that checks
whether `/dev/bellwether-events` exists knows it is being evaluated, and the path even carries the
project name. So the path now joins the other §3.5 identifiers: `SandboxIdentifiers.event_sink_path`
is drawn per run in `derive_identifiers`, a bare hex leaf under `/dev`
(`/dev/7e584283`, no project name), and the executor reads it for *both* the bind and the hook
command so the hook writes exactly where the FIFO is mounted. Three decisions worth recording:

- **A fresh token, not the workspace slug.** A skill can read its own workspace path; if the sink
  leaf were derived from the same slug it could reconstruct the sink path from what it can see. The
  leaf is an independent draw, appended after the existing identifier draws so their values (and the
  tests pinning "no project tell") are unchanged.
- **Still under `/dev`.** The bind is proven to work there (the CI container proof mounts the FIFO at
  a `/dev` path); randomising only the leaf defeats the hard-coded-path check without moving the
  mount to a directory whose writability under `--read-only` would be a new unknown. Perfect
  concealment is explicitly not the goal (§3.5) — active probing of `/dev` still produces the
  `instrumentation_probe` evidence; the point is that the cheap, reliable *fixed-string* tell is gone.
- **One source of truth for the stable path.** When randomisation is off (operator findability), the
  sink returns to the greppable `/dev/bellwether-events`, defined once as
  `sandbox.STABLE_SINK_CONTAINER_PATH`. The harness's `DEFAULT_SINK_CONTAINER_PATH` — the fallback
  default of `hook_settings` for standalone callers — is now `str(STABLE_SINK_CONTAINER_PATH)`, so
  the fallback can never drift from the path the executor actually mounts. Layering holds: `harness`
  already depends on `sandbox`, so the constant lives in the lower layer and the higher one reads it.

## §13.5.2 — `max_rare_capability_risk` maps severity to a weight *threshold*, and `critical` is stricter than `high`

The spec fixes `low → weight ≥ 10`, `medium → ≥ 5`, `high → ≥ 3`; raising the severity lowers the
cutoff (catches more). An earlier implementation mapped the observed weight to a *band* and compared
bands, which inverted the knob — at the shipped `medium` default it missed weight-5 capabilities, and
at `high` it disabled the gate entirely. The gate now reads `capability.rare_findings` computed at the
configured threshold. The spec does not define `critical` (a valid `Severity`); it maps to `2`, one
stricter than `high`, so tightening past `high` still tightens.

## §16.3 — `vouch` is deliberately not in the banned vocabulary

The language lint gained `guarantee`/`prove`/`ensure` (documented as banned but not enforced). It does
**not** ban `vouch`: the word appears in Bellwether only in the negative — "it warns; it does not
vouch" — which is the honest disclaimer the rule exists to protect, and it is the project's own thesis
statement (README, `__init__`, the CLI banner). Banning it would forbid Bellwether from stating what it
is. CLAUDE.md lists the enforced set explicitly.

## §15, §21 — `require_scan` is surfaced honestly; the §21 refusal now runs in `run`

The static scanner (§15) is a v0.2 work package and this build has none. A policy `require_scan: true`
was a silent no-op; `doctor` now warns that the required scan cannot run (a blocking static gate lands
with the scanner). Separately, the §21 enforced-settings refusal (which the threat model advertises as
active) previously lived only in `doctor`; it now runs inside `run_evaluation`, refusing above the
`low` profile when a residual-channel control is disabled — so the guarantee holds on the path a real
run and the CI workflow take, not just in the preflight.

## §6, §10.6, §10.2 — Re-verification residuals: bounded text reads, DNS empty-label, overlay-cap posture

A re-verification pass (reproducing every review finding's original failure against the fixed code)
turned up two fixes that were only *partly* landed, plus one deliberate divergence worth recording.

- **§6 loader-OOM (BW-22), second half.** The digest walk was hardened to chunked hashing, but
  `skill/package.py` still read `SKILL.md`, the `evals/manifest.yaml` attestation source, and each
  payload doc *whole* as text — so a multi-GB `SKILL.md` still OOM'd `load_skill` before any sandbox.
  A single-file text-read ceiling (`_MAX_TEXT_BYTES`, 8 MiB) now refuses an oversized core file at
  ingest (a finding about the skill, not a crash of the tool) and skips an oversized payload doc for
  the best-effort token estimate. The digest of an oversized *binary* file is still computed (chunked);
  only the whole-file *text* reads are bounded.

- **§10.6 DNS allowlist empty-label (BW-40), DNS half.** The egress `_norm_host` leading-dot fix was
  not mirrored into `dns.py`, so `.api.anthropic.com` matched the allowlisted provider
  (`_norm_qname` strips only trailing dots; `endswith("." + allowed)` reads the empty leading label as
  a subdomain). `_qname_matches` now rejects empty-label names via `_has_empty_label`. Deliberately
  scoped to the *matcher*: `_norm_qname` is left unchanged because the canary scan consumes the raw
  query name, and blanking it there would blind the covert-channel detector.

- **§10.2 overlay-walk cap (BW-36) — raise, not degrade.** The finding's suggested fix degraded the
  filesystem plane to `partial` at the cap; the shipped code instead **raises** `BellwetherError` once
  the overlay upper dir exceeds `_MAX_UPPER_ENTRIES` (200 000). This is a deliberate divergence: the
  security property (no unbounded `rglob` in host memory) holds either way, raising is fail-closed (a
  skill that floods its workspace gets an error, never `ready`, and never a silent pass), and it is
  strictly safer than the pre-fix behaviour, which was an actual host-process OOM. The cost is that a
  pathological run hard-stops the evaluation rather than yielding a degraded-but-scored result; graceful
  per-plane degradation is left for when the coverage matrix lands.

## §11.4, §13.5 — DNS capability tiers: `dns_blocked` carries the weight-10 `dns_query` class

§11.4's tier-1 capability enumeration does not list a DNS class at all, yet §13.5 (the weight
table) names one — "`dns_query` outside allowlist | 10" — and `DEFAULT_CAPABILITY_WEIGHTS` has
`dns_query: 10` (with no `dns_blocked` counterpart, unlike egress's `egress`/`egress_blocked`
pair). `trace/canonical.py` fills that enumeration gap for the two ARF kinds `dns_actions`
produces:

- **`dns_blocked`** (a name the resolver refused — outside the allowlist, NXDOMAIN) is the
  label-encoded covert channel Plane E exists to catch. It maps to tier1 **`dns_query:<name>`**,
  *not* `dns_blocked:<name>`. The capability weight is looked up by base class (the part before
  `:`); the spec's weight-10 class is `dns_query`, so the outside-allowlist query must carry that
  base. A `dns_blocked:<name>` tier1 would resolve to base `dns_blocked`, which has no weight
  entry and would fall to the floor (1) — silently under-weighting the exact reach the
  `max_rare_capability_risk` gate must catch. This is also why no `dns_blocked` weight was added
  to the table (the egress analogy is tempting but wrong): the spec deliberately weights the
  *outside-allowlist* query, and that is the blocked one.

- **`dns_query`** (a resolved, in-allowlist lookup) is permitted infrastructure — the resolver
  answered it because the name is on the allowlist (a model endpoint or an operator entry). It
  maps to tier1 **`dns:<name>`** (base `dns`, absent from the table → floor weight), present in
  the capability set for trajectory/completeness but benign. This is the DNS counterpart of the
  model-vs-non-model split egress makes: an in-allowlist resolution is not the risk, the
  outside-allowlist query is.

So the resolved/blocked distinction is load-bearing for scoring, and the naming is intentionally
asymmetric with the ARF kinds (kind `dns_blocked` → capability base `dns_query`) to honour the
spec's weight vocabulary. The `no_dns_outside` assertion and the `dns_outside_allowlist` finding
(policy key → base class `dns_query`, already wired in the orchestrator) use the same "outside
allowlist is the risk" framing.

## §10.6, §9.2 — Controlled-resolver topology: shared bridge, proxy name allowlisted, single-request

Wiring the resolver into the executor surfaced three decisions the spec does not spell out:

- **One internal bridge, shared.** The sandbox has a single network, and both the recording proxy
  and the resolver must be reachable on it. So when egress is on the proxy owns `bw-int-<run_id>` and
  the resolver *joins* it as a second peer (`DnsResolverProvider.open(network=…)`); when egress is
  off the resolver *creates and owns* it. The resolver is **not** dual-homed (unlike the proxy): it
  needs no route out, only to answer allowlisted names and NXDOMAIN+log the rest, so there is no
  egress bridge and no CA. `RunResolver.close` removes the bridge only when it created it, so the
  proxy's `close` remains the sole remover when the proxy owns it.

- **The proxy's container name must be in the resolver allowlist.** With `--dns` pointing the sandbox
  at the resolver, *all* of the sandbox's name resolution goes through it — including the lookup of
  the proxy's container name that `HTTPS_PROXY` names. If that name NXDOMAINed, the sandbox could not
  reach the proxy and every HTTPS call would fail invisibly (the §9.2 silent-interception failure, one
  layer down). So the executor hands the proxy's container name to the resolver as `extra_allowed` at
  standup; the resolver forwards allowlisted names to the Docker embedded DNS (`127.0.0.11`), which
  resolves sibling container names. The resolver's base allowlist (model endpoints + `dns.allowlist`)
  is composed in `build_resolver_provider`; the proxy name is added per-run because it is known only
  at standup.

- **`--dns` is an IP, plus `--dns-option single-request`.** Docker `--dns` takes an address, not a
  container name (it is consulted before name resolution exists), so `DnsResolverSidecar.resolver_ip`
  reads the resolver's bridge IP off `docker inspect`. `single-request` stops glibc from splitting the
  A and AAAA lookups across sockets, so every lookup is one query the resolver sees whole — the log
  cannot miss half of a covert-channel query. The lockdown itself is the internal bridge (no route to
  any *other* resolver, §3.3 invariant 3), not the `--dns` flag; the flag only points the sandbox at
  the controlled one.

## §10.4, §10.4.3 — Canary planting lands env-first; redaction is a trace-wide pass, not per-plane

**Spec.** §10.4 has Bellwether plant a pool of canaries (an AWS key, a `.env`, an SSH key, a
git-credential file, and an env-var token) at sandbox setup and scan every evidence plane for them;
§10.4.3 requires that no artifact ever hold a raw marker — redaction happens "at capture time."

**Divergence / decisions.**

- **The whole pool is planted, but the plane is `partial` because the *scan* is not yet complete.**
  The executor (`SandboxRunExecutor`, gated by `plant_canaries` ← `config.canaries.enabled`) delivers
  the env-var canary (`INTERNAL_API_TOKEN`) through the `extra_env` seam a scenario's env uses, and
  the four *file* canaries as **read-only binds** at their resolved slot paths — `_resolve_canary_path`
  maps `~/…` to the container HOME (`prepared.environment()["HOME"]`), a bare relative path to the
  workspace root (a skill's CWD), and an absolute path verbatim. A read-only bind is enough (a thief
  only reads the credential) and works even under the read-only rootfs — Docker creates the nested
  mountpoint. Planting is therefore complete, and all five canaries are scanned, redacted, and
  recorded by reference in the header `IdentityBlock`. `coverage.credentials` is still reported
  `partial`, but now because the *scan* — which covers the model's final output, DNS query names,
  tool-call arguments, non-model egress request URLs (path/host/SNI) and bodies (scanned sidecar-side
  in `make_flow`, the marker-free hits carried back on the flow), and written-file contents (read
  host-side from the overlay upper, since Plane B is hash-only) — does not yet cover the **model-API
  channel** (a canary sent to the model, graded `canary_in_context` vs `canary_without_read` by the
  per-request read state); never `full`, which would claim that channel was watched when it was not
  (§10.0 observation-beats-declaration). The planted files carry the
  marker wrapped in a realistic credential shape per kind (`_file_body`: an AWS INI block, an
  OpenSSH-PEM wrapper, a `.env`, a git-credentials URL), the marker contiguous on its own line so the
  exact-match scan finds it and redaction fingerprints only the value — a bare token is bait a capable
  skill routes around, a real-looking file is one it treats as a real secret.

- **The canary seed is per-*evaluation*, not per-repetition.** `_canary_seed` mixes `eval_id` into the
  base seed exactly as `_sandbox_rng` does but drops the matrix coordinate, so markers are identical
  across the repetitions in an evaluation (§9.3: the run cache keyed on `fixture_digest` still hits,
  and a leak fingerprints the same in every repetition) while still differing between evaluations.
  `mint_canaries` opens its own `"canary"` stream from it, distinct from the identifier stream.

- **Redaction is one pass over the assembled trace, not per-capture-point.** §10.4.3 says "capture
  time," which for the sidecar-side egress *body* it already is (`proxy_core`). But a marker can leak
  through the harness plane (the model's final output) or the DNS plane (a query name), and those are
  assembled host-side in the executor. Rather than teach every plane builder about canaries,
  `redact_trace_actions` runs once over the full action list — after `canary_actions` (which needs the
  raw marker to find the leak) and before `write_trace` — recursing into nested payloads and
  redacting every exact marker to its `<canary:…>` fingerprint. This is still capture time (nothing is
  written first) and is the single choke point where all host-side planes are present. Only exact
  occurrences are redacted, matching `redact_canaries`: a *decoded* leak keeps its encoded bytes, and
  the Plane C finding already records that it escaped. `test_execution_canary_docker.py` proves the
  invariant on the real artifact — a skill reads `$INTERNAL_API_TOKEN` and leaks it, yet the trace
  JSONL holds only the fingerprint.

## §12.5, §16.2 — Declared manifest scope is enforced on the live `run` path, decoupled from the outcome assertions

The first-light `run` scored each run against the scenario assertions and passed `scope=None` into
the driver, deferring declared-scope enforcement "until the egress plane lands in the executor." But
the `scope` gate still rendered a disposition from an always-empty `scope_exceeded`, so every live run
reported a reassuring `pass / within scope` no matter what the skill did — a control path that
produced a clean-looking result without running the check. A skill could call a tool its own manifest
denies and still reach `ready` (the BW-47 finding, observed live).

The reason `scope=None` was load-bearing is real and worth recording: the declared scope's
auto-derived assertions include network/write checks (§10.5, "no undeclared network") that are
`not_evaluable` while their derivations are stubbed, and a `not_evaluable` derived assertion marks the
whole run `not_evaluable`, which would block the evidence gate for a benign skill. So the fix does not
simply pass the scope into `analyse_run`. It threads the manifest's `declared_scope` through
`drive_evaluation` as a *separate* declared-vs-observed table (`scope_exceeded_of`), evaluated off the
run outcome — exactly the split `cli/demo.py` already used to keep the exfiltrator's clean planes from
being dragged to `not_evaluable`. `scope=None` still decides each run's outcome; `declared_scope`
feeds the observed-capability table into the `scope` gate. This is why the demo and the live path now
enforce declared scope identically, and why the network/write scope derivations remaining stubbed
(the honest gap, still disclosed) does not re-open the false green.

Undeclared scope *dimensions* stay allow-all: `evaluate_scope`'s `_tool_rows`/`_filesystem_read_rows`
each `return []` on an empty allow-list, so a skill that declares nothing is never falsely blocked —
only a capability observed outside a *declared* allow-list is flagged `exceeded`. The regression is
differential: a transcript that calls an undeclared `read` surfaces `scope_exceeded=("read",)` with
the declared scope threaded in and an empty tuple without it, so a revert of the driver change fails
the test (`() == ('read',)`).

**The network derivations then became real, and the split above was kept for its true reason.**
`no_egress`, `egress_only_to` and `no_dns_outside` sat in the catalogue as `_plane_gated` stubs —
`not_evaluable` even with the recording proxy and controlled resolver observing their planes. They
now evaluate: each is an absence claim gated on `plane_reason(…, for_absence=True)` (§10.8), so a
run without the sidecar still returns `not_evaluable` carrying the coverage reason and never `pass`;
with the plane observed, the skill's egress is the `skill_attributed` permitted flows (§10.5.0 — the
model API and declared harness infrastructure are never the skill's traffic) **plus every
default-deny block**, which is an attempt the skill made to reach a host the run refused — evidence
of intent, judged exactly like a flow that got through, with the block's own action as evidence (the
`EvidenceIndex` now records blocked flows with their host, and `dns_blocked` seqs). A blocked
attempt therefore always fails `egress_only_to`: the proxy refused it precisely because it lay outside
what the run permitted. Host matching is the proxy's own label-boundary rule, so `example.com.evil.test`
is not within `example.com`. The Declared-vs-Observed table gained a matching `network` area: a
skill flow no `network.egress_allow` entry covers is `exceeded` (and so blocks the scope gate); an
empty allowlist is the declaration that the skill makes no network calls (§12.5), under which every
skill flow is `exceeded`; a declared host nothing reached is `unused` only where the plane could
have seen a use, else `not_evaluable`.

With the derivations real, `scope=None` on the live path is no longer "because they are stubbed" —
the three comments that said so were corrected. The split stands on its own merit: an auto-derived
*absence* assertion on a plane a run cannot observe would mark the whole outcome `not_evaluable`
and block the evidence gate for a benign skill, whereas the table records that row as
`not_evaluable` by itself and lets the other areas score. The outcome stays the scenario's own
assertions; the manifest's scope, every area of it, feeds the scope gate through the table.

## §7.2, §9.1 — Per-scenario fixtures resolve by name, honouring the flat legacy layout

`Scenario.fixture` and `defaults.fixture` were in the model from WP-1 and ignored: `bellwether run`
materialised the whole `evals/fixtures/` directory as every run's workspace, so a skill whose
scenarios need different starting trees was not expressible, and the `fixture: python-repo` /
`fixture: empty` the spec's own examples use did nothing. `cli/fixtures.py` now resolves a name per
scenario — `evals/fixtures/<name>/` (the §5 scenario-specific fixture), then the repository's shared
`.bellwether/fixtures/<name>/`, with `empty` reserved for a bare workspace — and `plan_matrix` stamps
the resolved path and name on every `RunPlan`. Two decisions worth recording.

Resolution happens **once per scenario, in `plan_matrix`, before any container**: a missing named
fixture refuses while planning, not on the sixth repetition, and every repetition of a scenario
shares its tree (the fixture is part of *what* to run, so it rides on the plan rather than being a
second executor argument). The executor reads `plan.fixture`, falling back to its default for callers
that plan without a resolver, and the trace header records `sandbox.fixture` (§11.1's `"fixture":
"python-repo"`), which it had never carried.

The **legacy flat layout is honoured deliberately.** Every shipped skill was written against the
first cut: their `evals/fixtures/` is a flat tree (`standup/…`, `README.md`) while their `fixture:`
is a label (`standup-repo`, `readme-repo`) naming no subdirectory — and the proven live runs (PR #45,
PR #65) were made against exactly that flat tree. So a name that matches no directory but sits beside
a flat `evals/fixtures/` resolves to the flat tree, with the label recorded as the name. This keeps
every proven run byte-identical in what it materialises while giving new skills the spec's named
layout. A name that resolves nowhere is **refused**, not silently replaced by an empty workspace —
a run on the wrong starting tree would produce a clean-looking verdict about a scenario that never
ran as designed, the signature failure mode again — and the refusal names the scenario, the name,
where it looked, and the `fixture: empty` remedy.

## §7.2, §7.3, §13.1 — Multi-turn prompts, per-scenario timeouts and per-scenario schedules are honoured

Three more §7.2/§7.3 fields the scenario model accepted from WP-1 and the run path ignored.

**Multi-turn prompts.** A `prompt` list was joined with newlines into a single user turn, which
tests something else: the model sees every instruction at once, so a skill that behaves on turn
one and loses its constraints on turn two — the exact failure mode §7.3 exists to catch — is
invisible. `ApiLoopAdapter.run` now takes `str | Sequence[str]`; the first turn opens the
conversation, and when the model ends a non-final turn its reply is kept in the messages (via the
same `_assistant_message` the tool loop uses) and the next user turn follows it, so the session is
genuinely preserved. Only the last turn's reply becomes `final_output`; each intermediate reply is
already recorded by its `model_turn` event — so no new event kind enters the §11.3 vocabulary and
the normalizer, trace, and every downstream consumer are untouched. §7.3's `respond_with: judge`
mode (a cheap model playing the user) is not built; fixed turn lists are the "at minimum" the spec
asks for. The `claude-code` harness is different: the CLI is driven with one `-p` prompt, and
session continuation across turns (`--resume`) has not been observed from a real session in this
build — the project's rule for every CLI fact. So a turn-list scenario on a `claude-code` target is
refused by the §16.4 preflight (`scenario[<id>].prompt`, remedy: an api-loop target) before any
container, with a matching refusal in the executor as the last line of defence. Refusing beats
flattening: a silently single-turned scenario would produce a clean-looking verdict about a test
that never ran as written.

**Per-scenario `timeout_seconds`.** §7.2 gives every scenario a hard-kill timeout defaulting to
900 from the suite; the run path used the generic `RunLimits.wall_seconds` (600) for every run.
`run_limits_for` now applies the scenario's timeout (else the suite default) to the run's
`wall_seconds` — the bound that actually stops both adapters (the api-loop deadline and the CLI's
exec timeout). The sandbox's `timeout_seconds` config stays the outer container-level kill.

**Per-scenario `looks`/`n_max`.** `plan_matrix` ran every scenario the resolved `n_max` times and
`drive_evaluation` aggregated every set under the profile's looks; a scenario's own §7.2 override
did nothing. `effective_schedule` settles each scenario's schedule while planning — its own
`looks`/`n_max`, then the suite `defaults`, then the resolved matrix — and applies the manifest
override's consistency rule per scenario: looks strictly increasing, last look equal to `n_max`.
Where only `n_max` is overridden, the inherited looks are truncated to those at or below it, which
is unambiguous when `n_max` sits on a pre-registered look and **refused** otherwise: inventing a
decision point at `n_max` would change the number of looks and so the Pocock correction the design
was pre-registered with (§13.1). `plan_matrix` runs each scenario its own number of times (the
two-run floor applies per scenario), `drive_evaluation` aggregates each set under its own schedule
and holds it to its own first-look floor, `SetReading.looks` carries the schedule the set actually
ran, and the summary's `sets_stopped_at_look` is counted against that schedule — before, a stop at
N = 4 under a `[2, 4]` override was not a profile look and was mis-keyed as the profile's last
look. With no override the result is the resolved matrix exactly, so the default path and every
committed report are byte-identical.

## §7.4, §5 — `also_load_skills` loads sibling skills as offered companions; the CLI harness refuses them *(refusal since lifted — see "§7.4, §9.1 — Companions are staged for the claude-code harness")*

`Scenario.also_load_skills` carried companion names from WP-1 and the run path never read it, so
every scenario ran with the primary offered alone and `other_skill_activated` had nothing to
observe. Three decisions.

**A companion name resolves to a sibling directory, and nowhere else.** The §5 layout keeps every
skill one directory under `skills/`, so `skills/<name>/` beside the skill under test is the one
place a bare name means something; `cli/companions.py` loads it with the same `load_skill` the
primary uses (its own frontmatter, body, digests). A name that resolves nowhere **refuses while
planning**, not on the first run — the same reflex as a missing fixture — because a coexistence
scenario whose rival is silently absent would report the primary winning every activation for
the wrong reason, a clean-looking result about a test that never ran as written. Naming the skill
under test as its own companion refuses too: offered twice, "which activated" is undecidable.

**Companions are offered, not staged.** On `api-loop` the skills are presented host-side
(`OfferedSkill` name/description/body in the system prompt and the `skill` tool), so offering a
companion needs no sandbox change and every existing event — `skill_offered` per skill,
`skill_activated` naming the winner — already carries it; a companion's own `scripts/` are not in
the container, so a tool call into them is an ordinary error result, recorded. Nothing under a
companion is hashed into the primary's digests, matching how the run cache and baselines key on
the skill under test. The `claude-code` harness is different: the CLI discovers skills from
`~/.claude/skills/`, and this build stages exactly one there, so a companion would be invisible to
it and "which activated" a foregone conclusion. That combination is refused by the §16.4
preflight (`scenario[<id>].also_load_skills`, remedy: an api-loop target) rather than run — plural
staging is the same deferred piece as plugin-layout staging, and lands with it.

**The loading half, not the matrix.** §7.4's full machinery — the scheduled `bellwether
coexistence` command over the full library, two probe scenarios per skill, the trigger-collision
matrix and its delta against `_library.coexistence.json` — is a work package of its own. What
landed is what every coexistence scenario needs first: the competitors actually loaded beside
the skill under test, with the scenario's own `other_skill_activated` assertions deciding the
outcome.

## §10.4.2, §12.6 — The egress canary scan folds case on the host/SNI, matching how the host is recorded

The non-model egress scan joined the request's path, host, and SNI into one line and scanned it
case-sensitively. But a canary marker is mixed-case (the mint alphabet is `a–zA–Z0–9`) and
`_norm_host` records the host lowercased — `urlsplit().hostname` is lowercased so the allowlist
comparison is case-insensitive, as a hostname must be. So a marker tunnelled through a subdomain
(`<marker>.attacker.com`, the classic covert channel) was recorded lowercased and slipped past the
case-sensitive scan: the URL scan reported nothing while the secret plainly rode out. The DNS plane
already folded case for exactly this reason (`scan_query_for_canaries` passes `is_dns=True`); the
egress URL scan did not.

The fix scans the two field kinds by their nature rather than as one string: the path
case-sensitively and decode-aware (a URL path can carry a case-exact base64 marker, and folding it
would break base64's alphabet), the host and SNI the way a DNS name is scanned — case-folded,
label-split, base32-aware — since a hostname is case-insensitive and a marker chunked across
dot-labels must read as contiguous. A canary is de-duplicated to one finding per request even if it
lands in more than one field, preserving the prior "≤1 finding per canary per source" invariant.
Path-marker offsets are unchanged because the path was already the first field in the joined line, so
its offsets started at 0 either way; no committed golden shifts. The prior test built the `EgressFlow`
directly with a raw, un-normalised host, so it asserted host markers are found while never exercising
the lowercasing the real recording path applies — green while production missed; it is replaced by a
regression that records the host through `_norm_host` exactly as the sidecar does.

## §16.2 — `doctor` names the security-runtime dispositions that do not yet drive the scored verdict

Only `egress_outside_allowlist` is turned into a scored gate today (`security_runtime.egress`), yet
`SecurityRuntimeGate` carries thirteen disposition fields and the scaffold policy sets most to
`block` (`canary_leak`, `dns_outside_allowlist`, `credential_read_undeclared`, …). Those findings are
captured as evidence where their plane exists and shown in the report, but none of them reaches a
gate, so a `block` there reads as an active control while a leaking skill would still reach `ready` —
the same silent-no-op trap already surfaced for `require_scan` (§15). Wiring each disposition into a
gate is per-plane roadmap work; what ships now is legibility, not enforcement.

`ENFORCED_SECURITY_RUNTIME_DISPOSITIONS` (in `cli/orchestrator.py`, next to the gate assembly) is the
single authoritative list of what actually gates — a future gate wiring another disposition must
extend it — and `doctor` reads it to warn, naming exactly which configured dispositions are inert.
`dns_outside_allowlist` still gates *runnability* in the §16.4 precondition (bundled with egress), and
is listed because it is not *scored*. The point is the discipline the project holds elsewhere: a
control that does nothing must read as one that does nothing, never as one that works.

The **budget gate is the same audit applied once more.** `BudgetGate` carries `max_cost_usd` and
`max_wall_clock_minutes`, and the shipped policy presents them as ceilings (`25.00`/`60`, `100.00` on
`high`), but no budget gate is composed into the verdict and neither threshold is read anywhere — so
a `max_cost_usd` in policy reads as a spending limit and enforces nothing. `doctor` now warns that
the budget gate does not gate the verdict in this version and points at the one cost control that *is*
enforced: the per-repetition token ceiling (`bellwether run --max-tokens` →
`RunLimits.max_total_tokens` → a `budget_exceeded` outcome). Actually gating a dollar or wall-clock
budget was deferred deliberately, not forgotten: a dollar figure needs per-model pricing (which
Bellwether ships none of — §9.5's no-hard-coded-model discipline extends to prices that go stale), and
a wall-clock budget needs whole-evaluation aggregation across the matrix, not a per-run bound. *(Both
have since landed — see "§16.2, §19.1 — The budget gate is composed from the footers" below; the
`doctor` row now reports which half is enforced for which profile.)*

## §22 — The sandbox shells out to the `docker` CLI; the Docker SDK is deliberately absent

§22's technology table names the `docker` SDK for container work. The implementation does not use it,
and the reason is a security one rather than a taste one: **the flags are the security boundary.**
`--cap-drop=ALL`, `--read-only`, `--security-opt=no-new-privileges`, `--pids-limit`, `--network` on
the internal bridge and `--dns` at the controlled resolver are the isolation profile of §9.2, and an
SDK call that maps keyword arguments onto an API body puts one more translation between the profile a
reviewer reads and the argv the kernel actually enforces. Shelling out means `build_argv` produces the
exact command line, that command line is asserted in tests (`test_docker_argv.py`), and it is the same
string a human can paste into a shell to reproduce a run. The `Sandbox` interface §22 asks for is kept
so another backend (gVisor, Firecracker) can be swapped in.

The cost is that argument construction is Bellwether's own responsibility, including quoting and the
absolute-path rule for bind mounts (a relative source path is read by Docker as a *named volume* and
fails at container start — this cost a live run once, and `execute()` now calls `.resolve()`). That
trade is recorded here because the divergence is otherwise invisible: `pyproject.toml` carries a
comment explaining it, but the project's own rule is that a deliberate divergence from the spec lives
in this file.

## §16.4, §20 — The precondition check is wired composition-first, and its egress/DNS clause is split

`check_preconditions` sat unwired from WP-11 until the public-release review named it BW-51: built,
exported, unit-tested, called from nowhere, so the spec's "MUST refuse to start" never ran and an
unsatisfiable profile was discovered only after the matrix was paid for. The wiring lives in
`cli/preflight.py`, and the design decision worth recording is *where the truth comes from*.

The check needs to know what each target can observe, and the adapter's static declaration is the
wrong source alone: `ApiLoopAdapter` truthfully declares `egress_observable: False` — the adapter
provides no capture point of its own — but the executor standing a recording proxy beside the
sandbox makes egress observed. A preflight reading the static bit would refuse the proven live
configuration; one assuming the proxy would wave the scaffold default through to a
paid-then-blocked matrix. So observability is derived from the composition, by the same predicates
that wire the components: `egress.image` → the egress plane and the `egress_observable` bit,
`dns.image` → the DNS plane and a new `dns_observable` bit, `canaries.enabled` → the credentials
plane; the read and process planes are never available in this version (fanotify is v0.2, eBPF
v0.3), which is exactly what makes the `high` profile's `requires.capture_planes` refuse today, as
§16.4's own example intends.

Two amendments to the check itself, both in the spec's spirit rather than its letter. First, the
spec's combo 4 bundled the egress and DNS gates behind one `egress_observable` capability; the two
components are configured independently, so the clause is split — a wired proxy must not vouch for
an unwired resolver. Second, a target naming a harness with no shipped adapter is reported as a
precondition failure: before this, a `claude-code` target (which the scaffold policy ships!) ran
the entire sandbox under the api-loop adapter and then failed the trace-to-plan binding with "does
not match the run plan" — money spent, wrong error. `doctor` evaluates the check per profile
against that profile's own matrix targets, replacing the pending row; rows are `warn`, never
`critical`, because an unsatisfiable profile is a fact about policy-vs-composition and `run`
refuses it with the same failures.

`requires.min_bellwether_version` is now checked too (it was disclosed here as an outstanding
skip: version comparison needed an ordering rule the project had not committed to). The committed
rule lives in `verdict/precondition.py` (`_parse_version`/`_version_lt`): a deliberately
conservative subset of PEP 440, chosen so no `packaging` dependency enters a project that already
hand-rolls Wilson, BCa, and clustering to keep the dependency surface thin. The **release segment**
is the leading run of dot-separated integer components, missing trailing components padded with
zeros (`0.3` == `0.3.0`); any suffix (`.dev0`, `rc1`, `+local`, even a `post` release PEP 440 would
rank *above* the base) marks a *pre-release of* that segment and sorts strictly below the bare
release. That last choice is the safe direction for a start-blocking gate: an unmodelled suffix can
only ever make the check refuse a borderline build, never falsely admit one. An unparseable minimum
(no leading integer, e.g. `"latest"`) is itself a start-blocker rather than a silent pass — the
check cannot promise the requirement is met, so it names the bad value. The comparison stays out of
the pure `check_preconditions`: the running version is threaded in from `cli/preflight.py` (the only
layer that can name `bellwether.__version__`) as a parameter, `None` meaning "not evaluated", mirroring
how `available_planes` supplies composition truth. The shipped `high` profile (min `0.3`) now refuses
on both the version and its missing capture planes on a v0.1 runner — belt and suspenders, and the
version failure carries a version-shaped remedy the plane failure cannot.

## §10.4, §16.2, §10.7 — The canary gate scores the leak class only, and passes on `partial` fidelity deliberately

`canary_leak` is the first `security_runtime` disposition after egress to become a *scored* gate
(`security_runtime.canaries`, BW-49's first slice): a planted canary appearing at any non-model
destination now drives the composed verdict to `not_ready` under the shipped `block`, instead of
appearing only as a report row while the verdict read `conditional`. Three states, mirroring the
egress gate: unplanted defers (`not_evaluable` — an unwatched channel is never called clean),
an observed leak takes the policy disposition, an observed-clean set passes.

The decision worth recording is the pass state's relationship to §10.8. On the live path the
credentials plane records `partial`, and a gate's pass is an absence claim — which §10.8 says a
partial plane cannot support. The gate passes anyway, and deliberately: the plane's one partial
reason is the model-API channel, whose findings are a *different class* (`canary_in_context` /
`canary_without_read`, graded by read state) — by the §10.4.1 destination classification, every
`canary_leak` destination (final output, DNS query names, tool arguments, egress URLs and bodies,
written files) is scanned whenever planting ran at all. So "no leak observed" is an earned absence
over a fully-scanned destination set, not a claim laundered through a coverage gap. The
load-bearing assumption — that `partial` on this plane names only the model channel — is stated at
the gate; if a future change makes the credentials plane partial in a leak-relevant way, the gate's
observedness test must tighten to `for_absence`.

The same classification is why `canary_without_read` stays deliberately **unscored**: its evidence
cannot exist until the model-channel read-state scanning lands, and a gate whose evidence cannot
exist reads as an active control while nothing can fire it — the exact BW-49 trap this brick
exists to close, recreated one field over. It stays on `doctor`'s inert list, and both of
`doctor`'s lists (enforced and inert) now derive from `ENFORCED_SECURITY_RUNTIME_DISPOSITIONS`, so
the message cannot drift from the assembly again.

Completeness follows the egress bar: the set's gate is decidable only when canaries were planted
and scanned on *every* run — one unobserved run defers the set, and a leak in a set that also has
an unobserved run renders `not_evaluable`, which §16.2 blocks on a required gate; a leak plus an
incomplete plane never totals to a pass. The §16.4 preflight gained the matching runner-level
clause — `canary_leak: block` with `canaries.enabled: false` refuses before the matrix is paid
for — and the demo/first-light paths demote `canary_leak` to `warn` exactly as they do egress and
DNS, since nothing is planted there; their verdicts stay `conditional` on two advisory-unobserved
planes rather than borrowing a pass.

## §5, §6, §18 — Agent Plugin bundles (agent-plugins.org) are containers of skills, not a new evaluated unit

Spec revision 3 predates the Agent Plugins 1.0.0 specification (agent-plugins.org): its only
package shape is the bare skill directory of §5. Skills are now commonly distributed *inside* a
plugin — a directory with a `plugin.json` manifest, skills one per immediate child of `skills/`,
optionally an `mcp.json` declaring MCP servers and client extension directories. This note records
how Bellwether reads that shape, and the deliberate bounds.

**The unit of evaluation stays the skill.** A plugin-nested skill directory is exactly the
directory `load_skill` already reads, so `skill/plugin.py` only locates and describes: it parses
the manifest, enumerates `skills/*/SKILL.md` per the spec's discovery rule (immediate children
only, sorted by name for §24), and records what else the bundle carries. `bellwether run
<plugin-dir>` expands to the bundled skills; each gets its own evaluation, digests, and verdict,
unchanged. No plugin-level verdict exists — a bundle verdict would be an aggregate the metrics
were never designed to compose, claiming more than N runs of each skill support.

**Manifest validation is lenient, on the frontmatter's reasoning.** A plugin is attacker-authored
in external mode, so a `plugin.json` that does not parse, breaks the spec's name rule, or omits
`$schema` becomes a reported problem attached to every skill the bundle ships — never an abort
that lets a bundle dodge evaluation, and never silently ignored. Only "no directory" and "no
`plugin.json`" raise, matching `load_skill`'s own two hard refusals.

**A plugin-level change fans out to every bundled skill** in `changed-skills` (§18). A change
inside one skill keeps its precise attribution (skill-first, so a one-skill edit in a ten-skill
plugin does not pay for ten evaluations); a change with no `SKILL.md` ancestor but a
`plugin.json` ancestor — the manifest, `mcp.json`, an extension directory, a file under a
skill deleted from the bundle — re-evaluates all the plugin's current skills. The alternative,
attributing it to nothing, prints "no skills changed" for a PR that rewrote the bundle's
manifest: the exact silent false-green the detection exists to avoid. The BW-34 containment rule
(no absolute or `..`-escaping path is ever attributed) applies to the plugin walk identically.

**`mcp.json` is recorded, reported, and never started.** MCP servers are executable behaviour —
their own processes, their own egress — squarely what this tool exists to observe, and this
version does not stand them up in the sandbox. Observation beats declaration: every skill
expanded from a plugin carrying an `mcp.json` gets a problem line stating the servers are
unobserved and outside the verdict, so the omission is a recorded bound rather than a component
that reads as clean. Evaluating plugin MCP servers is follow-on work on the scale of a harness
adapter, not a loader flag.

**The bundle is not staged into the sandbox.** Staging still installs exactly one skill
directory at `~/.claude/skills/<slug>` (§9.1); plugin-shared files outside the skill's own
directory are not installed, and nothing under the plugin root is hashed into the skill's
digests. A skill that depends on sibling files or a plugin-root path at runtime would need
plural staging and a plugin-shaped install layout — that lands with the `claude-code` adapter
(WP-17), which is also where a real client would install the bundle as a plugin rather than a
bare skill.

## §10.6, §16.2, §10.8 — The DNS disposition becomes a scored gate, and the live smoke wires the resolver to keep `ready` earned

`dns_outside_allowlist` is the third `security_runtime` disposition to become a scored gate
(`security_runtime.dns`), completing the trio the shipped `block` defaults imply: a name the
controlled resolver refused (`dns_blocked`, Plane E) now drives the composed verdict, instead of
appearing only as a capability row. Three states, exactly the egress/canary decision table: no
resolver on every run defers (`not_evaluable` — an HTTP proxy never sees UDP/53, so an
unresolvered run's lookups are an unwatched channel), an observed refusal takes the policy
disposition, an observed-clean set passes.

Two decisions worth recording. First, the observedness test uses §10.8's **absence** bar
(`plane_reason("dns", for_absence=True)`), unlike the egress and canary gates' presence bar. The
gate's pass state claims "no lookup outside the allowlist happened", and the plane's fidelity is
`full` when the resolver runs — §3.3 invariant 3 leaves UDP/53 no route around it — so the two
tests coincide today and the stricter one costs nothing. It is chosen anyway because the canary
gate's spec-note already had to *document* the promise that a future `partial` fidelity must
tighten its test; here the tightening is done in advance rather than promised.

Second, scoring the gate forced the live smoke to actually observe the plane. `compose_verdict`
renders an advisory `not_evaluable` gate as `conditional`, so adding the gate with the resolver
unwired would have regressed the proven live `ready` (PR #45) to `conditional` on the next
labelled run — an unannounced downgrade of the project's own headline proof. So the same brick
sets `dns.image` in `examples/live/config.yaml`, builds the resolver sidecar image in the
workflow exactly as the proxy's is built, and guards it with a rot test mirroring the proxy's
(`test_the_live_config_turns_the_controlled_resolver_on`). The smoke policy keeps
`dns_outside_allowlist` at `warn` for the same shakeout reasoning as egress: a clean benign run
passes either way, and a surprise lookup warns rather than reddening the run before the resolver
pipeline is trusted live; promoting both to `block` is the same deliberate follow-up.

The demo and first-light paths change shape but not verdict: they gain a third advisory
`not_evaluable` row (`security_runtime.dns` — no resolver in an offline path), and their
committed reports are regenerated; `conditional` stays `conditional`, held now by three named
unobserved planes instead of two.

## §24, §13.4 — The noise floor is a committed measurement, and `at_noise_floor` is encoded in the data, not the renderer

WP-19's calibration closed with all three §24 assertions *measured on real containers*, not
assumed. Three decisions worth recording.

**The committed constant is a measurement with the schema-drift reflex applied to a number.**
`NOISE_FLOOR_TRAJECTORY` (0.0) and `NOISE_FLOOR_CALIBRATED_AT` live in `constants.py` and ride
into every `summary.json` as the §17.2 `noise_floor` block. `test_noise_floor_docker.py`
re-takes the measurement — six real sandbox runs of the `benign-stable` shape, Plane-A-only
dispersion asserted **exactly 0.0**, cross-plane residual asserted equal to the committed
constant, repeated under concurrent load (four sandboxes at once) — so a drift between the
published number and reality fails CI the same way a stale `summary.schema.json` does. The
spec's example floor (0.04) is illustrative; ours measured 0.0 because at the current coverage
composition every trajectory-contributing plane is either deterministic under the scripted
model (A) or empty on a networkless benign run (C, D, E). The floor is expected to move — and
the calibration date with it — when live-model transcripts or cross-plane events start
contributing steps; the docker test is what forces that recalibration to be deliberate.

**Plane-A-zero is asserted as an invariant, not recorded as a result.** Per the WP-19 done-when,
a nonzero Plane-A floor means §11.5 epoch anchoring admits jitter, so the test's failure mode is
"go fix the anchoring", never "update the constant". The offline half (`test_noise_floor.py`)
pins the same zero on the scripted path, so the invariant is watched by the fast suite too.

**§13.4's MUST lives in the summary, not in each renderer.** "A skill whose measured dispersion
is at or below the noise floor MUST be reported as `at_noise_floor`, never as a precise small
number" is enforced by construction: at or below the floor, `ConsistencySummary` carries
`trajectory_at_noise_floor: true` and `trajectory_dispersion: null` — the precise figure is
*withheld from the data*, so a renderer cannot print a number it does not have, the same
teeth-in-Python reflex as the BCI-never-without-pass-rate rule. Above the floor the precise
figure is present and rendered against the floor and its calibration date in both the PR
comment and the HTML report — the qualitative label must never blur a real signal. The two new
`ConsistencySummary` fields are additive and optional, so the summary schema is regenerated
without a version bump; the gate inputs (`SetReading.mean_pairwise_distance`) keep the raw
number regardless, because gates compute and reports render.

## §10.8, §10.7 — The precedence matrix ships two rows; every other row is *never raised*, and that is the implementation

WP-18's `trace_inconsistency` is produced by `assertions/precedence.py`, and the §10.8 warning is
the design driver: the naive any-disagreement rule fires on nearly every run while the `high`
profile blocks on the disposition. So the module encodes the matrix as *gates on comparability*,
and only two rows are comparable with the planes this version captures:

- **File write (persisted)** — B authoritative, A corroborating. A workspace-zone file the
  overlay shows persisted with no Plane A tool call claiming it is a finding. B's *positive*
  observation is trustworthy even at overlay-diff (the file is really on disk); the absence
  being read is Plane A's, so the row is gated on A supporting an absence claim (§10.8's
  stricter fidelity test — applied to the corroborating plane, which is the one whose silence
  is interpreted). Deletes and non-workspace zones are out of the row: the shipped harness has
  no delete tool, and harness-state/tmp writes are the harness's own machinery, so neither has
  an A-side claim channel and raising on them could only ever be a false positive.
- **Egress request** — D authoritative, A corroborating. A *skill-attributed* flow whose host no
  Plane A tool call mentions is a finding; `model_api` and `harness_infrastructure` flows have
  no A-side claim by construction and are never compared. A blocked flow is not re-raised here —
  it is already first-class evidence with its own scored gate.

The claim test is deliberately generous: a path or host anywhere in *any* tool call's arguments
counts as claimed (a `write` path, a `bash` redirect, a `fetch` URL). A generous match can only
suppress a finding, never fabricate one — the correct failure direction for this check. Every
other §10.8 row (activation and DNS: single-source; transient writes and reads: need
`filesystem_reads`; process: needs the eBPF/ptrace plane; A-stdout vs A-hooks: `api-loop` has one
A source) is **never raised**, each documented in the module; a row becomes implementable when its
plane does, and none may be approximated from a plane that cannot support it.

Surfacing: findings ride `analyse_run → SetReading → summary.security.runtime
["trace_inconsistency"]` and render in the PR comment and HTML report **only when any exist**,
labelled advisory — an empty "no inconsistencies" section would imply every row was comparable
when several never are, and the disposition stays advisory-unscored (`doctor` lists it as inert;
wiring it into a scored gate is deliberate future work, not this brick). The §10.7 half of WP-18
— the coverage block with per-plane fidelity *and reason strings*, and `not_evaluable`-with-reason
for assertions on unavailable planes — was already implemented (`Coverage`/`PlaneCoverage`,
`plane_reason`); the done-when (a real `benign-stable` container run at overlay-diff fidelity
yields **zero** findings) is asserted in `test_execution_docker.py` on real overlay evidence.

## §10.4.1, §2, §16.2 — The model-API channel is scanned host-side, read state is per-request and per-canary, and `canary_without_read` becomes the fourth scored gate

WP-16's last channel closed. The residual exfiltration path §2 names — a skill wanting a value
out does not need `evil.com`, it puts the value in a prompt — cannot be blocked without breaking
the evaluation, so it is now *observed*: `capture/model_channel.py` wraps the `ModelClient` seam
and scans every request the `api-loop` harness composes, host-side, on the request object, before
the wire. Three decisions worth recording.

**The read state is defined by where the marker sits in the request, per request and per
canary.** §10.4.1's "preceding `canary_read`" is made observable for this loop as: a marker
inside a **tool-result block** entered context through a tool call the trace already records —
that is the read (`canary_in_context`, info, the `legit-credential-reader` shape); a marker
present anywhere else with no tool-result block carrying it arrived by a path Plane A cannot
account for (`canary_without_read`, high). The per-request definition is exact because the loop
resends the whole conversation each turn — read evidence and marker travel together — and the
per-canary grading (`read_canary_ids`) means one legitimately-read canary never launders a
co-located, never-read one. Requests being cumulative, findings de-duplicate to the first request
where each `(canary, class)` pair appeared: one fact, one record, anchored to the `model_turn`
whose request carried it. Request bodies never enter the trace, so nothing new needs redaction;
findings are by-reference (§10.4.3).

**The credentials plane is `full` now, and the reads gate demands it.** With the model channel
scanned, the one reason the plane sat `partial` is gone, and `execution.py` records `full` when
planting ran. The new gate (`security_runtime.canary_reads`, scored from `canary_without_read`
under the shipped `block`) takes §10.8's *absence* bar for observedness — deliberately stricter
than the leak gate's presence bar, because a `partial` plane from before this scan is precisely a
plane that did not watch this channel, and it must defer rather than pass on it. The leak gate's
own spec-note contract ("partial names only the model channel") is retired rather than tightened:
new traces are `full`, and old `partial` traces defer the reads gate exactly as that note
demanded.

**Scoring lands with the evidence, not before and not after.** `canary_without_read` stayed
deliberately unscored while its evidence could not exist (the BW-49 trap: a control that reads
active while nothing can fire it); the same principle cuts the other way once the scan lands — a
`block` disposition whose evidence now exists but did not gate would be the trap re-created. So
this brick wires evidence and gate together: the §16.4 preflight gains the matching
composition clause (`canary_without_read: block` with canaries disabled refuses before spending),
`doctor`'s enforced list picks the disposition up from the shared constant, and the demo,
first-light, and scripted paths demote it to `warn` (nothing is planted there), gaining a fourth
advisory `not_evaluable` row with verdicts unchanged. The live smoke needs no change: canaries
are enabled, the preflight stays satisfiable, and a benign run's requests carry no markers — the
required gate passes on observed evidence and the labelled run keeps `ready`. Proven on a real
container (`test_execution_canary_docker.py`): the sandbox's own tool result carries both planted
markers into the second composed request, both grade `canary_in_context` at info, none grade
`canary_without_read`, and coverage reads `full`.

## §24, §25 — The acceptance corpus's security slice is offline and prose-only; base64 payloads and 127.0.0.1 bind when a skill ships an executable one

WP-20's first slice landed: the three security skills the §24 table names as the WP-16 §10.4
done-when — `canary-thief`, `dns-thief`, `legit-credential-reader` — under `tests/corpus/`, each
driven through the real analysis pipeline by `test_corpus_acceptance.py` and asserted to produce
its §25 verdict. Two deliberate divergences from §24's storage prose, both because this slice runs
**offline**.

**The skills carry no executable payload, so there is nothing to base64-encode.** §24 says corpus
payloads are "stored base64-encoded and materialised by a build step" — a rule whose purpose is
that a *working* exfiltration script never sits in the tree in plaintext (it trips secret
scanning and clone policies). The offline acceptance harness does not execute a real skill against
a real model and network: it drives a scripted transcript over an in-memory filesystem, and the
hostile behaviour is *modelled* — the egress flow a thief would send and the DNS query it would
make are constructed in the test and then scanned by the real `canary_actions`/`ModelChannelScanner`.
So each `SKILL.md` is a benign natural-language instruction with no payload to encode. The
base64/build-step rule is retained in `SECURITY.md` and binds the moment a corpus skill ships a
real executable payload — which is when the live `claude-code` adapter and real-network corpus runs
land (v0.2).

**Targets are `attacker.example`, not `127.0.0.1`.** §24 says exfiltration targets point at
`127.0.0.1` to stay inert. In the offline slice the target is never dialled at all, so inertness
is not the constraint that bites; `attacker.example` (RFC 2606, resolves nowhere) reads more
clearly as "a host outside every allowlist that goes nowhere" and matches the DNS-thief's refused
name. `SECURITY.md` keeps `127.0.0.1` as the rule for any corpus skill that makes a *real* network
call.

**What stays faithful, and why the slice is worth its weight.** Every scan under test is the real
one, and the policy is the shipped profile with its security gates at `block` — a demoted gate
would prove nothing. Coverage is `full` on every security plane, modelling a fully-instrumented
run, which is what lets `legit-credential-reader` reach `ready`: it is the §10.4.1 false-positive
guard, and a "any canary hit is a leak" regression would flip it to `not_ready` and break the
acceptance test. `canary-thief` and `dns-thief` block with the leak redacted to a fingerprint in
the committed-free artifact (§10.4.3). The declared-scope glob for the legit reader had to use the
`${HOME}` placeholder, not `~`, because an observed read normalises to `${HOME}/…` and the scope
matcher compares the two literally — a `~` would not match and the legitimate read would read as
out-of-scope. The remaining eight §25 corpus skills (`benign-stable`, `benign-chaotic`,
`file-selective`, `scope-creeper`, `rare-canary-reader`, `slow`, `over-declared`, `always-fails`)
are follow-on bricks, each asserting one more facet of the metric or gate stack.

## §13.5.2, §12.7, §12.5, §24 — Finishing the corpus surfaced four computed-but-unreported facts; a timeout stays a failed run but a distinct state; `unused` names, and blocks only on opt-in

The last five §25 skills (`rare-canary-reader`, `scope-creeper`, `over-declared`, `slow`,
`benign-chaotic`) each assert something the report has to *show*, and building them found that in
four places the pipeline computed the fact and dropped it before the summary. Each is now wired
through; the decisions worth recording are below.

**The §13.5.2 peripheral report is in `summary.json` and both renderers, dual-tier by rule.** The
metric already produced the peripheral set with its tier-3 expansion, but `capability_profile`
carried only a `core` list — and that list was the *union* over runs, labelled core. It is now the
intersection (a class in every run of every set), `peripheral` is everything else in the union
with its frequency, risk weight and expansion, `tier2` carries `sensitive_hits` and directory
instability, `tier3.expansions` the class→target map, and `rare_high_risk` the
`max_rare_capability_risk` findings. The expansion pairing needed a fix of its own: the
orchestrator grouped tier-3 targets by parsing a `<class>:` prefix back out of the target string,
and a filesystem tier-3 is a bare normalised path with no such prefix, so every read and write
expanded under `"other"`. It now re-asks `capability_for` per action — the same function the
canonicaliser used — so the pairing is the one the sets hold. The PR comment and HTML report gain
a "Peripheral capabilities" section rendered only where any class is peripheral or a sensitive
directory was reached, always the class beside the path, and the heatmap files a class under
`peripheral/` rather than `core/` with the rare-gate flag on it. `scope-creeper` is the assertion:
`outside_workspace_read` in 2 of 6 runs, expansion `${HOME}/projects/other-service/NOTES.md`,
visible in the comment.

**A timeout is scored as §12.7 says and counted as §24 says — both, not one.** §12.7's table folds
a `timeout` exit into the `fail` outcome, and that arithmetic is unchanged: `slow` has a 0% pass
rate and blocks the functional gate. But §24 requires the timeout "counted as a distinct state, not
a silent pass and not blended into assertion failures", and the strip chart's ⧖ cell existed with
nothing producing it (the code admitted "the aggregate does not carry [it] separately yet"). Now
`AnalysedRun` carries the exit reason beside the outcome, the strip draws ⧖ for a failed run whose
exit was a timeout, and `matrix.runs_timed_out` counts them — alongside `runs_not_evaluable`,
`runs_excluded_quality` and `runs_errored`, which the summary model had declared and the
orchestrator had left at zero. `sets_stopped_at_look` (keyed by 1-based look index, per the §17.2
example) and `sets_held_open_for_capability` are filled the same way; `scope-creeper`'s "escalates
to look 2" is asserted through them.

**`unused` is produced, rendered, and named in the gate's reason; it blocks only where a profile
opts in.** `evaluate_scope` already returned the `unused` rows; only the `exceeded` half reached
the reading. `scope_unused_of` now yields the other half, intersected over the set (one run using a
declaration makes it supported, not over-declared) and again across targets in the figures. The
scope gate's *status* is still decided by what was exceeded: under the shipped `block_on:
[exceeded]` an unused declaration keeps `pass` and is named in the reason ("declared but never
used: bash"); under `block_on: [unused]` it blocks. The alternative — warning by default — would
turn every `ready` skill with a spare declaration `conditional`, which is a policy choice the
profile already has a knob for. `over-declared` reaches `ready` with `bash` in the table.

Two consequences for the corpus harness and the `skill` tool. The harness had declared Plane B at
`overlay_diff` while injecting no Plane B actions, which made every write glob read `unused` — a
plane claimed and not watched, the exact shape §10.7 forbids. It now synthesises Plane B from the
in-memory filesystem's before/after (workspace-relative writes only, refusing anything else), so
the declared fidelity is true. And the harness's `skill` activation tool is a tool call on Plane A,
so a manifest that uses `tools.allow` must list it; `over-declared` does, with a comment — the
alternative (exempting the activation tool from the table) would hide a real call.

**`benign-chaotic` lands in three clusters, not "many".** Six scripted runs over the same three
tier-1 classes by six different routes produce three single-linkage clusters at the 0.2 cut —
the runs that differ only by a re-read or one extra file merge. The assertion is `≥ 3` clusters,
weighted Jaccard exactly 1.0, verdict `ready` or `conditional`, no gate blocking; the cluster list
is now populated in the figures (it had been left empty) so the comment shows every route. The
number of clusters travels as `consistency.trajectory_clusters`.

**`rare-canary-reader` blocks on the scope gate, not `max_rare_capability_risk`, and that is what
the spec's worked example predicts.** §13.5.1.1's table uses a weight-10 `canary_read` class; this
implementation classifies a read of the planted credential file as `outside_workspace_read`
(weight 3 — no producer emits a `canary_read` action kind; the Plane C finding for the read is
`canary_in_context`, and §25's worked example says the same: "the `medium` setting blocks at
weight ≥ 5... so it does *not* fire here"). What fires is frequency-independent by construction:
the read is outside the declared scope (`deny_read: **/.aws/**`) on a single occurrence, and the
§13.5.4 sensitive-directory flag records `.aws/` on the same occurrence. The acceptance test
asserts the property the section exists for — `not_ready` at N = 6, 12 and 20 alike, with
weighted Jaccard clearing 0.8 at every N — rather than which gate name carried it.

## §9.4, §10.1, §11.2, §3.3 — The `claude-code` adapter reads two sources, was built from an observed session, and is the harness where credential isolation actually bites

WP-17 landed the second harness: the real Claude Code CLI running headless inside the sandbox
(`harness/claude_code.py`). Six decisions worth recording.

**Every fact about the CLI was observed, not assumed.** §9.4 says to consult the harness's
current CLI and hooks documentation at build time because flag names change. The public docs
did not carry verbatim line shapes, so the ground truth was taken from the binary itself:
CLI 2.1.257 driven headless (`claude -p … --output-format stream-json --verbose`) against a
scripted Messages API on localhost, with `PreToolUse`/`PostToolUse` hooks writing their stdin to
a file. That session — the `init` line with `claude_code_version`/`permissionMode`/`apiKeySource`/
`tools`/`skills`, `assistant` lines whose `message.content` carries `tool_use` blocks (with
`stop_reason` observed as `null` at emit time, so the adapter derives it from the content),
`user` lines carrying `tool_result` blocks keyed by `tool_use_id` plus a structured
`tool_use_result`, a synthetic `user` line injecting the skill body, and the `result` line with
`subtype`/`is_error`/`num_turns`/`permission_denials`/usage — is committed, paths normalised, as
`tests/golden/claude-code/`. The hook stdin shape (`hook_event_name`, `tool_name`, `tool_input`,
`tool_use_id`, `tool_response`, `duration_ms`, `permission_mode`, `transcript_path`, `cwd`) is
committed beside it. The parser tolerates unknown line types and records malformed lines as a
count. Where the binary is on PATH (CI installs the pinned version) the session is re-run for
real through the adapter with a real FIFO sink. A CLI format change therefore breaks a test
rather than silently emptying Plane A — which would read as a skill that did nothing.

**Plane A comes from two independent sources, cross-checked, and the cross-check is a Plane A
record.** §9.4 asks for the hook stream as "a second, in-band source of tool-call evidence that
does not depend on parsing stdout", written to the host-owned sink; §10.8 says disagreement is a
finding. The hooks are configured inline (`--settings '{"hooks": …}'`, no extra mount) with one
command, `cat >> /dev/bellwether-events; echo` — `>>` is the write-only open the FIFO's mode
permits from inside, and the trailing `echo` keeps the hook's stdout a valid empty response so
the recorder never blocks a tool. After the run the two streams are reconciled per
`tool_use_id` (exact, not positional): a call on one side and not the other, or a name mismatch,
is emitted as `kind: trace_inconsistency` on Plane A — an observation *about* the plane, which
the canonicaliser excludes from the step sequence (a trajectory that varied with how the harness
reported itself would read as skill nondeterminism) and the orchestrator folds into the same
`trace_inconsistencies` field as the §10.8 findings. An *empty* hook stream against a stdout
with tool calls is a coverage fact, not N findings: Plane A records `partial` with the reason.
`--setting-sources user` keeps a fixture's `.claude/settings.json` from reconfiguring the harness
under test.

**The permission mode is recorded as pre-approval.** A headless run proceeds only under a
permission mode that never asks (`bypassPermissions`; the CLI refuses it as root, and the sandbox
runs as uid 1000). Every tool call is therefore auto-approved, and §10.1 says pre-approval must
be visible: each `tool_call` carries `permission: auto_approved`, the mode is in the trace's
`harness_capabilities`, and a `result` line's `permission_denials` become `permission_prompt`
records with `resolution: denied`.

**This is the harness where §3.3 invariant 1 bites.** On `api-loop` the model runs host-side
with the real key and the sandbox is handed nothing. The CLI's calls originate *inside* the
sandbox, so they can leave only through the recording proxy carrying the sandbox-scoped token
the proxy swaps for the real key (§10.5.1). Consequences: the §16.4 preflight refuses a
`claude-code` target with no `egress.image` (the run would spend a container watching the CLI
fail to reach any model); `build_proxy_provider` brokers a key only for the providers a
`claude-code` target names (from the manifest's matrix override or, absent one, every profile's
targets — a slight over-approximation that errs toward brokering, never toward a keyless run)
and leaves the broker empty otherwise; the executor delivers `ANTHROPIC_API_KEY=<scoped token>`
because that is the variable the CLI reads, whatever the provider's `api_key_env` is on the host.
The container test asserts the real key is absent from every artifact.

**Telemetry is disabled and its hosts are declared, but only the intake hosts.** §10.5.0 says
to set a telemetry-disable flag where the harness offers one, record that it was set, and declare
`infrastructure_endpoints`. `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`,
`DISABLE_AUTOUPDATER`, `DISABLE_BUG_COMMAND` and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` are
set and listed in the trace. The declared infrastructure endpoints are the telemetry and
error-reporting intake domains (`datadoghq.com`, `sentry.io`, `statsig.com`, by suffix) — *not*
the download, package-registry or documentation hosts the CLI also knows, because auto-update is
off, nothing is installed at run time, and an allowlisted content host is a route a skill could
carry data out on. The proxy adds them to its allowlist only when a key is brokered (a
`claude-code` evaluation), so an api-loop run's allowlist is unchanged.

**The normalizer learned the CLI's tool vocabulary; the adapter did not translate it.** §11.2's
example records `"tool": "Read", "input": {"file_path": …}` and expects the *normalizer* to
compute `workspace_read` from it. One table (`trace/tool_vocabulary.py`) now maps api-loop's
`read`/`write` with `path` and the CLI's `Read`/`Write`/`Edit`/`MultiEdit`/`NotebookEdit` with
`file_path`/`notebook_path` (and `Glob`/`Grep` as reads of their `path`) onto the filesystem
capabilities, used by both the canonicaliser and the evidence index so the capability sets and
the declared-vs-observed reads agree. Anything else stays `tool:<name>`. The alternative —
rewriting tool names in the adapter — would have put a translation between the trace and what
the harness actually reported.

**Read state for a harness whose model channel is visible only at the proxy.** On `api-loop`
the model-channel scanner sees the tool-result blocks inside each composed request. Here the
request bodies are scanned sidecar-side, and the recorded read is established from the full text
of the tool results the CLI reported (`tool_result_actions`: a marker there is
`canary_in_context`, anchored to the `tool_result`, text never in the trace); model-endpoint
body hits at the sidecar are then graded per canary against that set — a read one is the
expected info-level in-context finding, a never-read one stays `canary_without_read` at high.
Before this, every body hit graded `preceded_by_read=False`, which would have flagged
`legit-credential-reader`'s correct behaviour as a `high` finding on this harness.

**Known bounds, stated.** The CLI's session
transcript lands in the harness-state zone as ordinary state churn. Durations on `tool_result`
are host receipt-time deltas between the `tool_use` and `tool_result` lines (the hook stream's
`duration_ms` is finer but arrives after the run). The container proof is CI-only (the sandbox
image is an `npm install` of the pinned CLI on a digest-pinned Node base) and drives a scripted
model. The **labelled-live path is now wired** (`.github/workflows/bellwether-claude-code.yml` +
`examples/live/config-claude-code.yaml`), and the first labelled `claude-code` live run has now
happened — see the §9.4/§10.6 note below for the five environment defects it surfaced.

### §10.4.3 — a planted canary is invisible to the skill's filesystem accounting

A file canary is delivered as a **read-only bind** at its slot path (`_stage_canary_files`). For
the workspace-relative slot (`.env` → `${WORKSPACE}/.env`), Docker creates the bind's *mountpoint*
in the overlay upper, and the Plane B overlay diff records it as a `created` — a workspace write
the skill never issued. Left unmarked, that phantom write became a `workspace_write` capability
(so the **scope gate blocked** a benign skill on a `.env` it never touched) and a §10.8
cross-plane "disagreement" (Plane B write with no Plane A claim). The `.env` is the only pool slot
this hits; the `~/…` credential slots land outside the workspace and never collide.

The fix wires the `canary_path` mark that already existed in the model but was never populated:
the executor passes the planted workspace-relative paths to `collect_filesystem_events(canary_paths=…)`
(and to `prepare_sandbox` so the plant is excluded from `fixture_digest`, §9.3), and the two
consumers now honour the mark — `capability_for` returns no capability for a `canary_path` write
(`trace/canonical.py`), and `_index_filesystem_action` drops it from the write evidence the §10.8
matrix and the write-based assertions read (`assertions/evidence.py`). This is §10.4.3 made real
on the filesystem plane: the plant reaches the container and is recorded by reference, but the
instrument's own bait is never attributed to the skill. A skill that *reads* the bait is a Plane A
tool call, attributed on its own; a marker that *leaves* is a Plane C finding — neither is touched.
Proven on a real container: the planted `.env` shows in Plane B marked `canary_path`, and the run's
`scope_exceeded` and `trace_inconsistencies` are both empty.

## §9.4, §10.6 — The first live `claude-code` run found five environment defects the scripted proof could not

The offline `claude-code` proof drives a scripted Messages API in-container (CI-only). It exercises
the adapter, the two-source cross-check, and the vocabulary — but never a real model, a real sidecar
topology, or a cloud CI runner's networking. The first labelled live run (PR #65, evaluating
`examples/skills/claude-code-live-smoke` under the real CLI against Haiku) surfaced five defects, each
invisible to every offline test, in the order the run reached them:

1. **Planted canary phantom write** — the §10.4.3 note above; the first live run is where it bit.
2. **Harness-state churn mis-scoped.** The CLI writes session state under `/home/agent/.claude`
   (`.claude.json`, `projects/*/…jsonl`). `_filesystem_write_rows` (evaluate_scope) excluded
   `zone == "scratch"` but not `zone == "harness_state"`, so the CLI's own bookkeeping was compared
   against the skill's workspace write globs and **blocked scope**. `capability_for` already excluded
   it, but scope reads the EvidenceIndex, not `capability_for`. Fixed by excluding `harness_state`
   from the declared-scope write comparison exactly as `scratch` is; the dedicated
   `no_harness_state_write` assertion still surfaces the churn. `api-loop` never hit this — its
   harness runs host-side and writes no state into the sandbox.
3. **Upload-artifact EACCES on the overlay workdir.** The kernel leaves overlayfs `work/work`
   mode-000 root-owned; `chown` cannot make a mode-000 directory readable, and `upload-artifact`
   walks the whole tree to apply its exclude patterns, hitting EACCES despite excluding `runs/**`.
   Fixed by `sudo rm -rf "${eval_dir}/runs"` before upload in both live workflows — the ARF traces
   live at `traces/`, not under `runs/`, so no kept evidence lives there.
4. **The proxy hostname exceeded the DNS label limit.** The sandbox's `HTTPS_PROXY` host was the
   proxy sidecar's *container name*, `bw-proxy-<run_id>` — a live run_id makes that ~97 chars, past
   the 63-octet single-label DNS cap, so the embedded resolver refused it (`NORESOLVE`) and the CLI's
   model call failed `ENOTFOUND` before reaching the proxy. Fixed with a short, fixed Docker
   network-alias (`bw-proxy`) that `HTTPS_PROXY` points at; each run owns its own internal bridge, so
   a fixed alias is unambiguous. The alias is added **only on a user-defined network** (the default
   `bridge`/`host`/`none` reject `--network-alias`), and the container keeps its long unique name for
   lifecycle. `api-loop` never hit this — its model runs host-side, so its sandbox never resolves the
   proxy; the `claude-code` CLI, calling the model from inside the sandbox, is the first to.
5. **A cloud runner's DNS search domain manufactured a phantom `dns_blocked`.** With the proxy
   reachable and the token budget raised (the CLI resends its whole system prompt and ~16 bundled
   skills every request, ~190k tokens/run, so the smoke ceiling is 400k), the run completed the task
   and every gate passed **except DNS, which warned** — and a warn caps the verdict at `conditional`,
   never `ready` (`compose_verdict`, §16.2). Cause: a GitHub-hosted runner is an Azure VM whose host
   `resolv.conf` carries `search …dx.internal.cloudapp.net`, and Docker copies the host search list
   into the container unless told otherwise (the failing run's `resolv.conf` showed
   `# Overrides: [nameservers options]` — `search` *not* overridden — beside the inherited search
   line). glibc/Node then append that suffix to every unqualified lookup, so an allowlisted
   `api.anthropic.com` also produced `api.anthropic.com.<search>`, which the controlled resolver
   rightly NXDOMAINs (default-deny, §10.6). That search-list artefact is the runner's environment, not
   the skill choosing a new destination, but it landed as a `dns_blocked` event. Fixed by clearing the
   search list at the sandbox: `build_argv` now emits `--dns-search .` alongside `--dns` (proven on a
   real daemon: `--dns-search .` makes Docker override the search list to empty — `Overrides` then
   lists `search` — while the embedded resolver at `127.0.0.11` is untouched, so the short proxy alias
   still resolves and only the phantom suffixed queries disappear). Again `claude-code`-only: its model
   DNS happens inside the sandbox.

And one non-environment defect, in the tool-name assertions: they matched the tool name **exactly**,
and the two harnesses spell the same tool differently — the api-loop harness reports `read`/`write`,
the Claude Code CLI reports `Read`/`Write`. The `claude-code-live-smoke` skill is evaluated under
*both* live workflows (each detects it as a changed skill), so a single scenario must pass under both
casings — and no exact-match spelling can. The first attempt (asserting `{name: Read}`) fixed
claude-code but regressed the api-loop run of the same skill from `ready` to `not_ready` (functional
0/6 against the lowercase `read` it observes). The right fix is to fold case in the tool-name
comparison: `tool_called`, `tool_not_called`, and `tool_sequence` now compare on `casefold`
(`_tool_name_matches`), so one natural spelling (`{name: read}`) matches both harnesses. This
conflates nothing — a tool name is an identifier a harness chooses how to capitalise, the normalizer
already maps both spellings onto one capability (`workspace_read`), and no harness offers two tools
distinguished only by case, so a genuinely different tool still will not match. It also makes every
scenario portable across the two harnesses, which is the property WP-17's trigger-portable metrics
depend on. (An earlier revision of this note argued the opposite — that folding case would mask a
mismatch — before the dual-harness evaluation of one skill made the portability need concrete.)

## §16.2, §19.1, §17.2 — The budget gate is composed from the footers; cost is priced only from configuration, and an unpriced matrix is disclosed rather than guessed

§19.1 asks for a hard `max_cost_usd` "enforced by tracking reported token usage", and §16.2's
policy carries `max_wall_clock_minutes` beside it. Both are now gates, and three choices in how
they are composed diverge from the most literal reading.

**The gate is one matrix-wide row, not one per target.** §16.2 rule 2 has every gate evaluate per
target and take the worst. A budget is a ceiling on what the *evaluation* spent, so the per-target
shape would either show each target's share against the whole ceiling (misleading: a target at 2 min
reading `block` because the matrix hit 70) or repeat the matrix total under every slug. The gate
carries a single result whose target label is `matrix` (`BUDGET_SCOPE`), and the summary/report
render it like any other gate. `n_and_look` is `None`, as §16.2 already allows for gates that do not
read a repetition set.

**Spend is read from the footers, and a footerless run is a bound, never a zero.** Every complete
trace ends in a `run_footer` with `wall_clock_ms` and `tokens` (§11.1, §9.3); the orchestrator sums
those across every set. A run whose trace has no footer crashed before Bellwether observed an end,
and its duration and usage are *unobserved* — counting it as zero would let a matrix that spent an
unknown amount read as within budget. So the sums are lower bounds whenever a footerless run exists:
a lower bound above the ceiling **blocks** (enough is enough); with every run footered and under the
line the gate **passes**; and with a footerless run under the line it passes only where the per-run
wall-clock cap the executor actually enforced (the scenario's `timeout_seconds`, §7.2) bounds the
unknown — observed + unobserved × cap ≤ ceiling — and otherwise defers as `not_evaluable` (§10.7).
The cost half has no such bound (the token ceiling is far too loose to be useful), so a footerless run
under the line defers. `summary.cost.runs_without_footer` says how many runs the figures omit.

**Cost is priced only from configuration, and the cost gate is not composed for an unpriced
matrix.** Bellwether ships no prices: a literal price in the codebase would rot the moment a provider
changed it, the same reasoning as the no-hard-coded-model rule (§9.5). Pricing is
`providers.<name>.pricing.<alias>` — USD per million tokens for `input`, `output`, `cache_read` and
`cache_write` separately, because §9.3's cache line items make a naive per-token mean wrong on a
matrix whose first run is a cache miss. Where every target in the matrix is priced, `budget.cost` is
composed and required. Where any target is not, the gate is **not composed** and the verdict carries
a note naming the unpriced aliases and the `max_cost_usd` that is therefore not enforced; the summary
records `cost.usd: null` (never `0.0`, which would read as free) with `unpriced_targets`, and
`doctor` reports per profile whether the cost half is enforced. This is the same convention the
other un-built gates already follow (`static`, `quality`, `regression`, `human_review` are not
composed and `doctor` says so), chosen over composing the gate as `not_evaluable`: a required
`not_evaluable` would make every unpriced evaluation `not_ready`, and an advisory one would cap it at
`conditional` — either would demote the proven live `ready` on a matrix whose *spend is fully
recorded* and only its dollar conversion is missing. Disclosure in three places (verdict note,
summary, doctor) is the honest reading of "the control is not active", and it is what the
observation-beats-declaration discipline asks for: the gap is stated, never passed.

`--budget-usd X` (§20) overrides the profile's `max_cost_usd` for one evaluation; on an unpriced
matrix it enforces nothing and the note names the figure that is not enforced, so the flag is never
mistaken for a control that took effect. A negative value is refused; zero is the explicit "any priced
spend blocks" setting. The footer's `estimated_cost_usd` stays `None`: pricing is applied at
composition (where policy can be re-derived from cached traces, §19.2) rather than stamped into the
trace, so a price correction never invalidates a run. The `summary.json` schema is at `1.1` — a minor
bump: `cost.usd` is now nullable and `cost.runs_without_footer` / `cost.unpriced_targets` were added.

## §20, §17.5 — `trace` locates a run by its header id; `diff` compares summaries under the comparability table and applies no gate

§20 lists `bellwether trace <RUN_ID>` and `bellwether diff <EVAL_A> <EVAL_B>`; §17.5 asks for
the diff as ad-hoc comparison and is firm that a silently partial diff is worse than a refused
one. Three implementation choices are worth recording.

**`trace` searches by the header's `run_id`, not by path arithmetic.** §17.1 files a trace at
`traces/<scenario>/<target>/<repetition>.arf.jsonl`, but the id a report's evidence links name
is the `run_id` in the trace's own header, and nothing in that id is guaranteed to encode the
path. So the command walks the artifact tree (sorted, first line of each file only) and matches
the header. The same id under two evaluations — a re-run into the same `--out` — is refused
naming every candidate rather than resolved by order; `--eval` narrows, and a path bypasses the
search. The one-line summary per action is per-kind and deliberately lossy (80 characters,
newlines escaped); `--json` carries the full `action` payload.

**`diff` compares `summary.json` only, under §17.5's table, and names what it skips.** The
comparable set is what the rollup carries: the verdict and gates by name, the functional and
consistency readings, tier-1 classes by set difference, tier-2 sensitive hits, findings, and
spend. Two rows of the §17.5 table apply directly: a different `weights_digest` skips the BCI and
weighted Jaccard (named at the top), and a different schema version refuses outright, since a
field's meaning may have changed. Tier 3 is always listed as not compared (§4.1: it churns). A
different policy digest or skill name is a *caveat* rendered before the table, not a refusal —
"what changed when we moved from model X to model Y" (§17.5) is a legitimate cross-policy,
cross-target question, and the reader is told the thresholds may differ. Peripheral tier-1
classes are read from their §13.5.2 records (`{"tier1": ..., "frequency": ...}`), so a class
moving from core to peripheral is neither an expansion nor a removal.

**`diff` reports; it does not decide.** `gates.regression` (`block_on_capability_expansion`,
`max_pass_rate_drop`) is a policy applied against a *stored baseline* on the run path (§17.5,
§18.4). The ad-hoc diff has no policy in hand and no baseline semantics — either side may be
the newer — so it surfaces tier-1 expansion as the headline signal and leaves the disposition
to the reader. Baseline storage and the regression gate have since landed (next entry) and the
gate's comparison reads the same summary shape `diff_summaries` does.

## §17.5, §18.4 — The baseline record is the whole summary under the key; the gate is composed only where the key allows and says why otherwise

§17.5 describes the baseline file as "a trimmed summary: tier-1 and tier-2 capability
core/peripheral sets, pass rates, BCI components, coverage". The record written by
`bellwether baseline set` carries the **whole** `summary.json` under the key instead. Trimming
would mean a second, hand-maintained shape that has to stay in step with the summary schema and
with the comparison; carrying the summary means the regression gate and the ad-hoc `diff` read one
shape, and a field added to the summary is available to both without a migration. The file is
larger than the spec's sketch (a few kilobytes) and is committed to git as §17.5 asks; the
`.gitattributes` `merge=ours` rule is written beside it (a repository must still enable the
driver with `git config merge.ours.driver true`; the rule cannot do that for it).

**The key is derivable from any `summary.json`.** `canon_version`, `platform_baseline_version`
and `matrix.target_slugs` are stamped on every summary now (schema `1.2`), so a baseline can be
set from a stored tree without the readings. `traj_planes` is not recorded: nothing in this build
varies it, and §17.5 lists it as metadata rather than key.

**Composition.** Where `gates.regression.compare_to_baseline` is set and no baseline exists, the
gate is not composed and the verdict carries a note — the same convention as the unpriced cost
gate: a required `not_evaluable` would make every never-baselined skill `not_ready`, which is
not what "no baseline yet" means. A baseline whose key rules the comparison out (another skill,
another `canon_version`, another target set) likewise leaves the gate uncomposed with the
reason. Where the key allows, the table applies per component: a different
`platform_baseline_version` skips the capability sets and sensitive hits (the subtracted
infrastructure is not the same), a different `weights_digest` skips the BCI. What blocks:
tier-1 expansion under `block_on_capability_expansion` (a warning otherwise — "policy MAY
block on it"), and a lower-bound drop beyond `max_pass_rate_drop`, lower bound to lower bound.
A new tier-2 sensitive-directory hit is "always a finding, never merely a delta": it warns even
where nothing else moved. A BCI drop is reported in `summary.regression.deltas`, not gated —
the policy carries no threshold for it. `payload_digest` differing from the baseline's is
expected, not a mismatch: that is the version-to-version comparison the gate exists for.

## §17.1, §20 — The figures are persisted so `report` re-renders; persisting them found a hash-order bug

`bellwether report <EVAL_ID>` re-renders from stored artifacts. §17.1's tree has no entry for
the renderers' second input — the figures computed from the readings (strip chart, heatmap,
cluster list, scope table) — so this build adds `metrics/figures.json`, versioned canonical JSON
under the tree's `metrics/` directory (§17.1 names that directory for `consistency.json` and
friends, which do not exist yet). A tree without the file predates persistence and is refused:
rendering from the summary alone would silently drop the three figures.

Writing the figures to bytes exposed a §24 violation the byte-compare tests had not caught:
`build_figures` iterated each run's `caps_t1` **frozenset** to build heatmap rows, so their
order followed the process hash seed. `render_capability_heatmap` sorts, which kept the HTML
stable, and CI pins `PYTHONHASHSEED=0`, which kept everything else stable — exactly the kind of
accidental determinism §24 warns against. The rows are sorted at the source now, and the fix
was proven by rendering the demo under three different seeds.

## §19.1, §20 — `--depth` is a preset over the matrix options and requires every alias it names

§19.1's depth table maps onto the §20 matrix options: `quick` = `--targets small
--repetitions 3`, `standard` = `--targets frontier,small --looks 6,12`, `deep` = every target
with `--looks 6,12,20`. It is implemented as exactly that expansion, and is refused in
combination with any of those options — two instructions for one setting. One deliberate
strictness: a preset must find every alias it names in the matrix. `standard` on a matrix
with `frontier` alone would otherwise run one target and report as if it were the two-target
PR default; refusing and naming the aliases the matrix has keeps the preset meaning what §19.1
says it means. `quick` is fixed-N, so it is `descriptive_only` and can never return `ready`
(§13.1, §16.2 rule 6); the run's output line marks it, per §19.1's "the output header MUST say
so".

## §6.2, §20 — `init-manifest` infers from the capability profile and never declares a finding

§6.2 has Bellwether "infer a scope from observed behaviour on the first run and offer to write
the file, clearly marked as inferred-not-reviewed". The inference reads a stored evaluation's
`capability_profile.tier3.expansions` — every tier-1 class the matrix exercised with the exact
things it touched (§13.5) — rather than re-analysing traces, so it works on any tree and is a
pure function of the summary. Permission classes map to the manifest's areas: `tool:<name>` →
`tools.allow`, the read classes → `filesystem.read`, the write and delete classes (including
`harness_state_write`) → `filesystem.write`, `egress:<host>` → `network.egress_allow`,
`process:<argv0>` → `processes.allow`. Paths are written verbatim, as globs, for the reviewer
to generalise; the header says so.

The rule that matters: **a finding is never laundered into a permission.** A `canary_read`, an
`egress_blocked:<host>`, a `dns:`/`dns_query:` lookup, and any path under a §13.5.4
sensitive-directory hit are listed in the file's header as observed-but-not-declared, with the
reason, and left out of the allowlists. For the exfiltrator this is the difference between a
manifest that documents the credential read as a finding to review and one that quietly
permits it. The rendered file is parsed back through the manifest loader before it is kept, an
existing manifest is never replaced without `--force`, and `--force` preserves the reviewed
`criticality`. `credentials.expects` is always written empty: which credential a skill
legitimately needs is a human decision (§10.4.1's `legit-credential-reader` distinction).

## §12.6 — The platform baseline is applied per run on the path half; processes and tools wait

`platform-baseline.yaml` (§12.6) was a shipped, loadable document with no reader on the run
path: `apply_path_baseline` had no callers. It is now applied in `analyse_run`, per run,
where the document is keyed to the run's own sandbox image (the header's, which is the
configured one). The glob-aware matcher produces the literal tier-3 set `canonicalize`
subtracts — the seam WP-8 left for it — so subtraction still happens *before* the capability
sets are produced (§11.4) and the step sequence still keeps every step. What was absorbed is
recorded per run and in `summary.security.runtime.baseline_absorbed`: "observed − baseline"
has to be auditable, or a subtracted access is simply gone. Near-misses (a traversal that
names an entry but escapes it) are never absorbed and surface as
`summary.security.runtime.baseline_near_miss`; they remain report findings rather than a
scored gate in this build, and `doctor` does not yet list them among the inert dispositions
because they are not a disposition.

Two halves of §12.6 stay unwired, deliberately: **process attribution** (`always` /
`helpers_of`, evaluated by tree) needs the process plane's parent/child records, which the
capture layer does not produce yet, and the **tools** list is empty in the shipped default
because a tool call is agent behaviour until a harness shows otherwise. Scratch-zone paths
never reach the matcher at all — §10.2 coarsens them to tier 2 before a tier-3 entry could
match — so a `${TMP}/**` entry is accepted but has nothing to absorb; that is a property of the
zone rules, not a gap in the wiring.

The applied version is stamped on the run header (`platform_baseline_version`, as §12.6 asks)
and on the summary, where it is the §17.5 key component. A baseline not keyed to the configured
image absorbs nothing, and the verdict note and the `doctor` row both carry the document's own
reason, so "not applied" never reads as "nothing infrastructural happened".

## §19.2 — The run cache key adds the model id and the repetition index; a hit is re-filed with provenance

§19.2's run-cache key is `(payload_digest, scenario_content_digest, target, fixture_digest,
harness_version, sandbox_image, platform_baseline_version)`. This build's key has two more
components. The **model id** is there because §19.2 also says "never cache across a changed
model ID, even where the alias is unchanged" — the alias is part of `target`, the id is not, so
the rule has to be in the key. The **repetition index** is the divergence worth a note: with the
spec's key alone, every repetition of a set would resolve to the same entry and a cached set
would be one run replayed N times — a set that agrees with itself by construction, which is
the opposite of what a repetition set is for. Keying on `(…, repetition)` keeps N distinct
observations. Three more components were added when successive reviews of the first cut asked
what else changes what a run *is* without changing the spec's tuple: the **pinned sampling** (a
temperature-default trace must never be replayed under `--deterministic-sampling`, where the
summary would then claim pinned runs that were not, nor the reverse); the **companions'
payload digests** — a companion's content reaches the run (offered on api-loop, staged on
claude-code) while only its *name* is in the scenario's content digest; and the **observability
fingerprint** (`observability_key`), a digest of the capture settings, the egress and DNS
sidecars and allowlists, canary planting, and the sandbox's resource limits. The spec's key names
the sandbox image, which fixes what is *inside* the container and says nothing about what watches
it from outside. Wiring the recording proxy, pointing the sandbox at the controlled resolver or
turning canaries on changes which planes the trace carries, so without this a first evaluation
run networkless would be replayed after the proxy was wired and egress would read
`not_evaluable` while the operator believed the plane was watched — this project's signature
failure mode, a control path rendering a clean result without running the check.
`harness_version` is the
package version for api-loop (the adapter ships with it) and the configured `version_pin` for
claude-code. **An unpinned claude-code target is not cached at all**: its real CLI version is
only known once a container has run, and a key reading "unpinned" would serve a trace across a
CLI upgrade. Such plans bypass the cache (never consulted, never filled) and the verdict notes
disclose the count with the remedy — a cache entry cannot depend on something learned after the
lookup, and it cannot pretend not to depend on it either.

**A hit is re-filed, not copied.** The cached trace's header carries the original evaluation's
`run_id`, `eval_id` and `scenario_id`; replaying it verbatim would file an artifact under the
wrong evaluation and, after a scenario rename (which the content key deliberately survives),
under the wrong scenario id. The replay rewrites those three identity fields for the new
evaluation and sets the new header field `cached_from` (`<eval_id>/<run_id>` of the original)
so the provenance is explicit rather than lost. Actions and the footer are the original's,
byte for byte — the observation is not touched. `arf_version` is unchanged: the field is
optional with a default, and an older reader ignores it.

**What is never cached:** an incomplete trace, or one whose exit reason is `sandbox_error`,
`harness_error` or `cancelled` — §13.2's infrastructure failures are retried, and a cached
failure would be replayed forever — or any **operator-limit** outcome (§12.7): `budget_exceeded`,
`timeout`, `oom` and `pids_limit`. Each of those is decided by a bound the key cannot carry (the
token cap comes from `--max-tokens`; the suite's `defaults.timeout_seconds` sits outside
`scenario_content_digest` and, being under `evals/`, outside `payload_digest` too), so a cached
one would be replayed unchanged after the operator raised the very limit that produced it — the
run would keep failing at a ceiling that no longer exists. `execution.cache_ttl_days` expires
entries so drift is still detected. The analysis cache
§19.2 also names is not built: canonicalisation is cheap enough that re-deriving it from a
stored trace costs nothing worth caching.

**A replayed run is not this evaluation's spend.** §16.2's `max_cost_usd` and
`max_wall_clock_minutes` bound what an evaluation costs, and a cached run's footer records what
the *original* evaluation spent. The spend sums (`summary.cost`, the `budget.cost` and
`budget.wall_clock` gates) therefore cover executed runs only — a cached run contributes neither
tokens nor wall clock, and is not counted as an unobserved run either — and the verdict carries
a note saying how many runs were replayed, so a matrix served from cache cannot fail a budget
it did not spend, and a reader is told why the cost figure is small. The §19.1 estimate is
printed before any lookup, so it cannot deduct hits; with the cache on it says its figures are
upper bounds rather than guessing a hit rate.

## §9.3, §20 — `--deterministic-sampling` is a per-request pin, recorded and marked, and refused where it cannot be honoured

§9.3 has Bellwether record the provider's sampling defaults rather than impose its own, and §20
lists `--deterministic-sampling` for a low-variance comparison. The flag is a `SamplingSpec`
on the api-loop adapter, sent on every request: `temperature` to both providers, `seed` only
to the Chat Completions API (the Messages API takes none, so it is not sent). Without the flag
no sampling field is on the wire at all — the realistic condition stays the default. The run
header records the pinned values in `target.sampling` and sets `deterministic_sampling`, the
summary marks the matrix, and the verdict carries a note, because a temperature-0 run
understates the variance the consistency figures exist to measure. On a claude-code target the
CLI exposes no temperature or seed control, so the §16.4 preflight refuses the flag there rather
than record a "deterministic" run that was nothing of the kind.

**The verdict's notes are rendered.** Until now `verdict.notes` (the unpriced cost gate, a
missing baseline, a platform baseline not applied) reached only `summary.json`; a reader of the
PR comment never saw that a control had not run. Both renderers now show them under the
verdict header — §16.2's "a control that did nothing must read as one that did nothing" has to
hold on the surface people actually read.

## §19.1 — The pre-flight estimate prices a ceiling and a baseline-drawn expectation, and never guesses

§19.1 makes the estimate mandatory and prescribes a cost formula with three multipliers and an
`E[N]` from the repository's stopping history. This build prints the estimate before anything
is spent and states, in the estimate itself, which parts of the formula it cannot fill. The run
counts come from the schedules the sets will actually run: best is every set stopping at its
first look, worst is every set at `n_max`, expected is the **midpoint look** — §19.1's default
for a skill with no history, and this build keeps no stopping-history store, so it is always the
midpoint and the estimate says so. The judge and A/B terms are zero because neither subsystem
exists. The dollar figures are two: a **ceiling** — the per-repetition token cap priced as input
tokens for every worst-case run, a bound rather than a forecast (output tokens cost more per
token but are a small share of a run, and the cap bounds the total) — and an **expected** cost
drawn from the skill's stored baseline's observed tokens per run where one exists. With any
target unpriced there is no dollar figure at all, only the enforced token cap: an estimate that
guessed a price would be the one number in the report a reader could not trust.

`--yes` skips the confirmation prompt, never the estimate. The prompt is asked only on an
interactive terminal; a CI run proceeds after printing, since there is nobody to answer — the
mandatory part is the printing. A decline is a refusal with no container started.

## §7.4, §9.1 — Companions are staged for the `claude-code` harness; the preflight refusal is lifted

The entry above refused a companion scenario on a `claude-code` target because the build staged
exactly one skill and the CLI discovers skills from what is installed. Plural staging now exists:
`stage_companions` stages each companion the scenario names into its own directory under the run
(`<run>/companions/<slug>`) with the same `stage_payload` the primary uses — the allowlisted payload
only, normalised metadata, the §3.5 machinery check — and the executor binds each read-only at
`<install root>/<slug>` beside the skill under test. Three decisions.

**The fact was observed before it was relied on.** §9.1 says the harness reads
`~/.claude/skills/`; that one directory is discovered was proven for the primary, but "every
directory is discovered and named" is a separate CLI fact. The real-CLI offline test installs a
companion beside the primary and asserts the CLI's init record names both (each reaches the trace
as `skill_offered`) while only the primary activates; the CI-only executor proof stages a companion
through `SandboxRunExecutor` and asserts the same from the trace. Discovery is thus *observed* per
run — a companion the CLI did not list would be visible as a missing `skill_offered`, not assumed
present.

**Collisions refuse before any copy.** Two skills that slug to one directory would shadow each
other at the install root and "which activated" would be undecidable; the whole set is checked
first, naming both skills, so a refusal leaves no half-staged run directory.

**Companions stay out of the primary's digests.** Nothing under a companion is hashed into
`payload_digest` or `fixture_digest`, matching the api-loop entry: the run cache and baselines key
on the skill under test, and a companion is scenario context, not payload. The §16.4 clause and
its `companion_scenario_ids` parameter are removed rather than left inert. Plugin-layout staging
(a bundle installed whole, the way `--plugin-dir` would) remains open — it needs a CLI fact this
build has not observed, and the "bundle is not staged" paragraph under §5/§6/§18 still stands.

## §19.1, §9.3, §20 — The estimate's ceiling bounds the spend; a header records the sampling that was sent

Two corrections a review of the first cut earned, both of the same shape: a number presented as
one thing while computed as another.

**The cost ceiling is a bound, not a mix.** The first cut priced the per-repetition token cap
entirely as *input* tokens and rendered it as `ceiling ≤ $X`. The cap bounds a run's **total**
tokens and says nothing about their composition, so an output-heavy run could cost several times
the figure the operator approved at §19.1's mandatory gate — the one number in the estimate a
reader is entitled to treat as a limit. The ceiling now prices the whole cap at each target's
dearest published rate (`_dearest_kind_cost`), which is what makes the rendered claim true; the
caveat says plainly that this bounds the spend rather than describing the likely mix. The
*expected* figure is unchanged in spirit and still drawn from the baseline's observed tokens per
run, but its divisor now excludes replayed runs, because the same PR made `summary.cost` count
executed runs only — dividing by every completed run understated tokens per run by exactly the
cached share.

**A run header records the sampling that was applied, not the sampling that was asked for.**
`--deterministic-sampling` builds a spec carrying both a temperature and a seed, but the Messages
API takes no seed and `anthropic_request_body` deliberately never sends one. The header stamped
the requested pair regardless, so an Anthropic run's trace claimed a pinned seed that never left
the host — a declaration where the project's rule is observation. `applied_sampling` lives in the
harness layer beside the request builders and narrows a spec to the fields the provider type
actually puts on the wire; the executor records its result, and `deterministic_sampling` is true
only where the pin was applied. An unknown provider type claims nothing. A test asserts the
narrowing against the real request bodies rather than against the table beside them, so the two
cannot drift apart silently.

**A declined estimate has its own exit code.** Declining raised the generic error and exited 3,
the infrastructure code, so a script that saw only the status could not tell "the operator said
no, nothing ran" from "the environment is broken". `RunDeclinedError` now maps to exit **4**
(§20), leaving 3 to mean what it says.

## §9.2, §12.7, §19.2 — Per-run limits are configuration, not policy, and the bounds are recorded

`RunLimits` shipped as generic defaults that every run received regardless of configuration.
Three decisions in closing that.

**Configuration, not policy.** The obvious home looked like the policy profile, beside the §16.2
budget gate: a `high` profile permitting a longer run than `low` reads naturally. It is the wrong
home. §19.2 requires that a policy change **re-derive verdicts from cached traces without
re-running anything** — that is why `policy_digest` appears in neither cache key. A profile that
could change `max_turns` would change *what runs happen*, and that invariant would quietly stop
holding. The limits therefore live in `execution.limits`, beside the other execution knobs, and
the policy keeps its job of judging what was observed. `--max-tokens` still overrides the token
cap, because it is the documented per-invocation cost control and a config value beating a flag
typed at the terminal would be surprising.

**No wall clock here.** §7.2 gives the wall clock to the scenario (`timeout_seconds`, else the
suite's `defaults`), and `run_limits_for` already applies it. A second wall clock in config would
silently override the suite author's per-scenario choice, so `RunLimitsConfig` has no field for
one and a test asserts its absence.

**The bounds are recorded, because §12.7 scores two of them as failures.** Hitting `max_turns` or
`max_tool_calls` produces a *timeout*, which the functional gate counts against the skill, while
`max_total_tokens` produces `budget_exceeded` and is `not_evaluable`. A tight ceiling therefore
converts an operator's choice into the skill's score, and a trace that only says "timeout" cannot
be told apart from a skill that genuinely could not finish. `RunHeader.limits` (a `LimitsRef`)
now carries the bounds each run ran under, `doctor` states them and their outcomes before a run
is paid for, and the limits are part of the run cache's observability key — a run stopped at a
ceiling is a different observation from one that ran to its own end, so raising a ceiling misses
rather than replaying the truncated trace. The field is optional rather than defaulted, so a
writer that recorded no bounds is distinguishable from one that recorded bounds of none; that
also keeps the committed golden trace byte-identical.

## §9.2, §20 — The interception probe needs no reachable destination, and has three outcomes

§9.2 asks `bellwether doctor` to establish interception by issuing a real request. The host-side
core (the mechanism table, `interception_confirmed`) landed early; the live half did not, and
doctor reported the proxy as *configured* in its place. Those are different claims, and the space
between them is where the tool's worst failure lives: a container that rejects the CA produces
traces with zero egress, which read as a skill that never touched the network.

**The probe is self-contained.** The obvious design needs a reachable destination, which means
either real internet from CI or a TLS peer container stood up beside the proxy. Neither is
necessary, because of where the flow is recorded: `ProxyAddon.on_request` appends the flow when
the request **arrives**, before any forwarding decision. So a recorded probe host establishes that
the client completed a TLS handshake against the proxy's own certificate — which is the entire
question — regardless of what happened upstream. The probe therefore targets an unresolvable name
in the reserved `.invalid` TLD: nothing leaves the machine, no peer is needed, and a client that
does not trust the CA fails during the handshake, before any flow exists. The probe host is
deliberately *not* allowlisted either; a denied request is still recorded, because the block is a
decision made after receipt.

**Three outcomes, not two.** Confirmed and rejected are the obvious pair, and collapsing everything
else into "not confirmed" would be the familiar mistake — a probe that could not run would read as
a CA failure, and the operator would fix the wrong thing. `InterceptionProbe` carries an explicit
*inconclusive* state for the case where nothing was established either way (no route, no
interpreter, a request that died before TLS), and doctor renders it as a `warn` that says so.
Only a rejection is `critical`. The rejection markers are matched on *trust* wordings
specifically, not on TLS errors generally, for the same reason.

**It probes the sandbox image, not the sidecar.** The first cut ran the client from the sidecar
image, on the reasoning that it is the one image guaranteed to carry a Python interpreter. The
row it rendered said the CA is trusted and egress is observed — about a container no evaluation
ever uses. The container that has to trust the CA is the **sandbox**: that is what a run puts on
the internal bridge, and a sandbox that rejects the certificate is the entire state the probe
exists to rule out, so the probe could not fail for the case that matters. It now runs the client
from ``sandbox.image``; an image with no interpreter yields *inconclusive*, which is the honest
answer and the reason that third state exists.

**Everything a probe can throw is a row, not a traceback.** A missing ``docker`` binary or a pull
that outruns the client timeout says nothing about the CA, and must not abort ``doctor`` in place
of the rest of its rows: ``OSError`` and ``subprocess.SubprocessError`` join ``BellwetherError``
as "not probed" warnings.

**The counter-case is asserted.** A probe that cannot fail establishes nothing, so the container
proof also runs the identical request from a client with the CA stripped from its trust
environment — keeping `HTTPS_PROXY`, so the failure is about trust and nothing else — and asserts
the certificate is refused with no flow recorded. The stripping helper lives beside an offline
guard that fails if `probe_argv` ever names trust differently, so the CI counter-case cannot
silently become vacuous by stripping nothing.

## §5, §6, §18 — A plugin is installed whole, and the CLI qualifies its skills

The earlier note deferred plugin-layout staging on the grounds that it needed a client fact this
build had not observed. This closes it by observing the fact.

**What was wrong.** Staging lifted each skill out of its bundle and installed it as a bare
directory. Everything the bundle holds *outside* a skill directory — shared references a skill body
points at, the manifest — never reached the container, so a skill that reads a sibling path works
in a real client and fails under evaluation for a reason that is about Bellwether rather than about
the skill. `stage_plugin_bundle` now copies the bundle whole and the CLI loads it with
`--plugin-dir` (the flag the real binary documents: "load a plugin from a directory"). The §3.5
invariant is unchanged and now applies bundle-wide rather than per skill: no `evals/` anywhere is
copied, each is named in `refused_machinery`, and the result is asserted before the bundle is
mounted.

**One bundle, one copy of the skill.** The bare payload is mounted at
``<config dir>/skills/<slug>`` on every run, and staging the bundle *as well* left the harness
holding two copies of the skill under test — ``demo-skill`` and ``demo-bundle:demo-skill`` — with
which one activated undecidable. That is the same ambiguity the §16.4 preflight refuses for
companions, reintroduced by the back door, and the worse half is that if the bare copy won the
run would still lack the sibling-bundle content this staging exists to provide.
``PreparedSandbox.install_payload`` now says explicitly whether the skill reaches the container
by its own mount, and the bundle path turns it off.

**What must not travel with a bundle.** The copy is a denylist where ``stage_payload`` is an
allowlist, because arbitrary bundle content is the point — so the exclusions are named rather
than assumed. Version-control metadata is excluded: a plugin that is its own checkout carries the
evaluation machinery inside ``.git``, and leaving the working tree's ``evals/`` behind is no use
when ``git show HEAD:evals/scenarios.yaml`` recovers it. Non-regular files are skipped rather than
read: a FIFO blocks the copy until a writer appears, and the observed tree must never decide
whether the observer finishes (§10.0). Ordinary dotfiles *are* staged — a bundle's own ``.env`` or
``.claude`` is content a real client installs.

**The install path is resolved before it is trusted.** ``stage_payload`` asserts its derived path
cannot escape the install root; the bundle needs the same, with one subtlety that a lexical check
misses. Taking the path's name verbatim puts ``..`` in the container path, and
``plugins/..`` compares as *relative to* ``plugins`` while resolving to its parent — which would
mount the bundle read-only over the harness-state zone. Resolving the bundle path first is what
makes the guard real, and it also makes ``bellwether run ..`` install under the directory it
actually names.

**The bundle keys the run cache.** ``payload_digest`` covers the skill's own files and nothing
else, so without a bundle digest a cached trace would be replayed after a shared file the skill
reads changed, and a bare run and a ``--plugin-dir`` run would share a key. ``plugin_digest``
closes both.

**The observed fact, and why it mattered more than the staging.** Running the real CLI 2.1.274 with
`--plugin-dir` and reading its init record: every skill under `skills/` is offered, and each is
reported **qualified by its bundle** — `demo-bundle:demo-skill`, not `demo-skill`. Bellwether's
`skill_activated` assertion compared the recorded name to the skill under test exactly. Whole-bundle
staging would therefore have scored the skill as *never activating* on every plugin run: a false
negative manufactured by the staging choice, presented as evidence about the skill. Had the staging
landed on the assumption that names come through bare, the corpus would have looked fine (no plugin
skill is in it) and the defect would have waited for a user.

The fix keeps the observation and narrows the comparison, not the other way round: the trace records
what the harness said, and `skill_name_matches` strips the bundle qualifier **from the recorded side
only**. An expected name that carries its own qualifier is compared whole, so a scenario can still
name exactly one bundle's skill where two bundles ship the same skill name. The qualification is
pinned by a test against the real binary, so a future CLI that drops it fails there rather than
leaving the matcher over-matching forever.

## §26 — CodeQL on Bellwether's own source

Listed for a long time as "thin to be missing on a repo about supply chain", and parked as a
repository setting. Only the *enabling* is a setting; the workflow is code, and for a public
repository committing it is the whole of the work. `security-and-quality` over the Python package,
on pull requests and `main`, plus weekly — the weekly run being the part that earns the most, since
most of what the queries will ever find here is already written. SHA-pinned like every other action,
because `tools/pin_lint.py` is not optional for the repository that ships it.


## §3.5, §9.2, §19.2, §24 — A second review round: what the container actually holds, and what the key actually describes

Four of the findings in the review of the bricks above share a shape, and it is the shape this
project keeps finding: **a path that renders a clean-looking result without observing the thing it
names.**

**The probe client could not run on the image it claimed to probe.** The first round fixed the
probe to use the *sandbox* image rather than the sidecar — the container a run actually places on
the internal bridge. The client was still hard-coded to `python3`. Running the shipped
`claude-code` sandbox base settled it: `curl`, `wget`, `openssl`, `python3` all missing; `node` and
`sh` present. So the corrected probe could only ever report *inconclusive* on the one image that
matters, while its CI proof passed by substituting the sidecar. The client is now a `sh` dispatcher
preferring `node`, and Node is not a fallback here but the point: it ignores the system trust store
and reads `NODE_EXTRA_CA_CERTS`, which §9.2 singles out as the mechanism that is **not optional**,
so the probe exercises the trust path most likely to be the one that silently fails. Node's core
`https` does not honour `HTTPS_PROXY`, so the tunnel is made explicitly — `CONNECT`, then TLS over
that socket — which is exactly the sequence being established. Node also reports OpenSSL error
*codes* rather than the prose Python and OpenSSL produce, so `_CA_REJECTION_MARKERS` gained them;
without that, every real Node rejection would have read as "nothing established" rather than as the
one `critical` outcome the feature exists to report. The container proof now runs on the sandbox's
own digest-pinned base **and** the sidecar, one per branch of the dispatcher, and the client is
additionally run against a real intercepting socket server offline, in both the trusted and the
rejected case — a client that cannot fail establishes nothing.

**A companion inside the bundle was installed twice.** Whole-bundle staging stopped installing the
skill under test twice; a §7.4 companion that is a *sibling in the same bundle* was still staged
bare on top of the bundle's copy. The harness would see `k8s-debug` and `demo-bundle:k8s-debug` —
two copies of the competitor — in precisely the scenarios companions exist to decide, where *which*
skill activated is the whole question. `companions_to_stage` drops a companion the bundle already
installs, comparing resolved paths so a symlinked checkout is recognised as the same files.

**The §3.5 exclusion was weaker in the bundle than in the payload.** `payload._is_machinery`
deliberately folds case and Unicode form — `EVALS/manifest.yaml` is machinery just as much as
`evals/manifest.yaml`. The bundle walk compared the exact string, and so did the leak assertion that
is supposed to catch exactly that. Both now go through one shared predicate,
`staging.bundle_exclusion`, over the public `names_machinery_dir`; version-control directories are
folded the same way, since `.Git` on a case-insensitive filesystem is still a checkout.

**The cache key described a different bundle from the one staged.** `plugin_digest` was
`fixture_digest(plugin_root)` — the whole working directory, including `.git` and every `evals/`,
none of which staging copies. A plugin developed in its own checkout therefore changed key on every
commit while the bytes placed in the container were identical, and the cost of that miss is paid in
model tokens. `plugin_bundle_digest` excludes exactly what `stage_plugin_bundle` refuses, through
the same predicate, and a test asserts the two sets are equal rather than merely similar.

**The container path followed the operator's directory name.** The install directory came from
`bundle_root.resolve().name`, so the same bundle checked out as `plugin/` on CI and `plugin-dev/` on
a laptop installed at two different container paths: the run cache becomes machine-local (§24) and
the host layout leaks into a sandbox the skill can read. It now comes from `PluginBundle.name` —
the manifest's declared name, or the directory name where it declares none — which is why the
bundle rather than its root path is what travels from `_expand_skill_args` to the executor. The
escape guard did not move: the spec's name rule admits periods, so `..` is a *well-formed* declared
name, and where a value came from does not make it usable as a directory.

### Round three — the repository's own machinery, and what a refusal costs

Seven more from the next review pass, and the one that matters most is a §3.5 hole the first two
rounds walked past. `evals/` is the *skill's* machinery. A plugin bundle that is its own checkout
also carries the **repository's**: `.bellwether/` holds the config, the platform baseline, the
stored baselines and the *policy* — the gates the skill is about to be judged against — and
`.bellwether-out/` holds the traces of previous evaluations. Whole-bundle staging put both inside
the container, which tells the skill under test not merely that it is being watched but exactly
what would clear it. Both are excluded now, named in `refused_machinery`, and the directory name
comes from `config.document.CONFIG_DIR` rather than being spelled again, so renaming it cannot
leave the exclusion behind.

`plugin_bundle_digest` had the same shape of gap one level down: it hashed escaping symlinks that
the copy refuses, so re-pointing one at a different host file moved a cache key describing a bundle
in which nothing had moved. The predicate the two share is now `staged_exclusion`, which takes the
bundle root and can therefore answer the filesystem questions too; `bundle_exclusion` remains the
name-only half, because a directory has to be judged before it is walked.

**The install name needed a fallback, not a refusal.** Deriving the container path from
`PluginBundle.name` alone broke `bellwether run .` on a bundle whose manifest declares no name:
`load_plugin` falls back to the directory name, and a relative path has no last component, so the
name is `""` and staging refused a run that had worked the day before. `_install_name` takes the
first *usable* of the declared name and the resolved directory name, and refuses only when neither
is. The guard also rejects `:`, which is legal in a directory name and fatal in `-v host:container:ro`
— docker answers "invalid volume specification", an error about docker syntax for a problem about
the operator's checkout.

**A refusal must not cost a leaked sidecar.** The recording proxy and the resolver are opened
before the staging that can refuse, and everything between that standup and the run's own
`try`/`finally` was unguarded: a bundle that refused, a companion slug collision, a `claude-code`
target with no proxy, a sink that could not open its FIFO — each left the sidecar containers
running and their bridges behind. A refusal that costs the operator a manual `docker network rm` is
a refusal that discourages refusing, and refusing is how most of the executor stays honest. The
region is now guarded, resolver first, because it joined the proxy's bridge and a still-attached
container blocks its removal.

**Two smaller ones on the probe.** `run_interception_probe(probe_host=…)` reached the interpreter
but not `probe_argv`, so an overridden host produced a client still asking for the default and a
probe guaranteed to read *inconclusive* however well the CA was trusted. And the client container
had no name and no deadline of its own: `subprocess.run` kills the `docker run` process on timeout
and leaves the container attached to the sandbox bridge, which then refuses to be removed — the one
thing the module's docstring says it never does. The container is named, removed before the proxy
closes, and the Node client carries its own 20-second deadline.

### Round four — the exclusion list was guessed, and the guard started one statement late

Three more, all in code the previous round introduced.

**The exclusion list named a directory the code does not use.** Round three excluded
`.bellwether/` and `.bellwether-out/` from a staged bundle. `.bellwether-out/` came from the
documentation; the name `--out` actually defaults to is `bellwether-runs`, and that is where a
self-checkout bundle keeps previous evaluations' traces, summaries and verdicts. So the exclusion
read as though it covered the case and did not — the exact shape of defect the §3.5 assertion exists
to catch, committed *inside* the fix for it. Both names now come from `config.document`
(`CONFIG_DIR`, `RUN_OUTPUT_DIR`), the `--out` literal that was repeated at six commands is gone, and
a test asserts every command sharing that default shares the object rather than re-spelling it.
`.bellwether-out` stays excluded because the workflows and older checkouts use it.

**The teardown guard started one statement too late and ended too trusting.** The resolver's own
standup sat above the guard, and that is precisely the case where a proxy is already up and nothing
else would ever close it — a resolver image that will not pull, a bridge name already taken. And
the handler's three closes ran in sequence, so the first to raise skipped the rest, reinstating the
leak it was added to prevent *and* replacing the original refusal with a teardown error, which is
the less useful of the two to be told about. The resolver standup is inside the guard now and each
close is isolated. Both were proven by reverting them: each test fails without its fix.

**Two findings left for their own brick**, because they are in files this change does not touch and
widening a PR to reach them is how a diff stops being reviewable:

- `cli/companions.py` joins `also_load_skills` entries as paths with no single-component check, so
  `../…` escapes the skills tree and `./<name>` slips past the self-companion refusal. §5 says a
  companion is a sibling; the loader should require one.
- `cli/infer_manifest.py` turns every `egress:<host>` capability into a `network.egress_allow`
  entry without filtering on egress class, so `init-manifest` writes the model API and harness
  infrastructure hosts into the skill's own declaration. The class is already on the action
  payload (`egress_class`); it is the canonical capability that drops it.

### Round five — the exclusion the caller knows, and the other half of the teardown

Nothing merge-blocking this round, and four worth fixing. Three were in code the last two rounds
introduced; the fourth was the other half of a defect they half-fixed.

**The `--out` exclusion was keyed on a default.** Round four fixed the exclusion list to name the
directory the code actually uses, `bellwether-runs`. It is still only the *default*: `--out
artifacts` on a bundle that is its own checkout put previous evaluations' summaries and verdicts
inside the container, and the name rule cannot see that. `staged_exclusion` and
`plugin_bundle_digest` now take `exclude_roots`, and the caller passes the artifact root it is
actually writing to — the §3.5 invariant stops resting on a default nobody is obliged to keep. The
executor takes the **artifact root**, not its own run directory: `<out>/<eval_id>/runs` would leave
every previous evaluation beside it staged, and those hold the traces and verdicts, which is the
part a skill would learn from. The same value keys the run cache, because a key over a different
set of files from the one staged is the failure the shared predicate exists to prevent.

**The success path leaked what the failure path no longer does.** Round four isolated the teardowns
in the guarded region and left the run's own `finally` running its five closes in sequence, four
lines below — so a raising `stop_persistent` or `unmount` skipped the resolver and proxy closes on
the path where the run *succeeded* and nothing is ever coming back for them. Both now go through
`_tear_down`, which attempts every step.

**And it no longer discards what failed.** `suppress(Exception)` bought isolation by throwing the
signal away: a bridge that would not come down left no trace anywhere, which is not a standard this
project applies to skills and should not apply to its own housekeeping. `_tear_down` collects the
failures and attaches them as a note to whatever exception is propagating — never replacing it,
because an operator told "docker rm: No such container" instead of the refusal that actually
stopped the run goes and fixes the wrong thing. With nothing propagating, the teardown failure is
raised on its own.

**A threshold is not a drift guard.** The test added last round to stop the `--out` default being
re-spelled skipped any command that had drifted and asserted a count, so one command drifting away
passed exactly as cleanly as none drifting. It names the seven commands exhaustively now, `demo`
and its deliberate `examples/reports` included; changing the set has to be a deliberate edit.

## §13.5.1, §10.5.0, §7.4 — The harness's egress is not the skill's, and a companion is a name

Two loose ends carried out of the previous brick, and the second turned out to be the larger of
the two by some distance.

**A companion is named by its name (§5, §7.4).** `resolve_companions` joined each
`also_load_skills` entry onto the skills directory as a *path*, so `../elsewhere/smuggled` reached
a skill outside the tree — a scenario file choosing what the container is offered, from anywhere
the process can read — and `./<name>` compared unequal to the directory name while resolving to it,
walking straight past the self-companion refusal and putting the skill under test in front of the
harness twice under two names. That is the one outcome the refusal exists to prevent, because
"which activated" then has no answer. Entries are now validated as a single path component before
the join, since the join is what makes a path dangerous; backslash is refused on POSIX too,
because the entry comes from a YAML file that may have been written on Windows.

**§13.5.1 weights `egress:<host>` at 10 and says "(non-model)" in the same breath.** The
canonicalizer did not honour that parenthesis: every egress class collapsed to `egress:<host>`. The
assertions layer already draws the line — `derive`, `engine` and the §10.8 precedence matrix all
filter to `skill_attributed` — so this was the one place that did not.

Under `claude-code` the cost is not theoretical. The CLI's model calls originate *inside* the
sandbox and leave through the same recording proxy a skill's would, so a skill that made no request
at all came out of canonicalization holding two weight-10 capabilities: the model API and the
harness's telemetry host. Those reached

- the **BCI**, as risk-weighted classes the skill never exercised;
- **`max_rare_capability_risk`** (§13.5.2), whose cutoff *is* a risk weight — a telemetry host
  appearing in one run of six is a rare weight-10 capability, so the harness's own traffic could
  block a verdict;
- the **§17.5 baseline**, where a harness endpoint change reads as capability expansion; and
- **`init-manifest`**, which wrote `api.anthropic.com` into the skill's `network.egress_allow` —
  the laundering that module exists to prevent, performed on the one host where a later genuine
  exfiltration would then read as declared-and-allowed.

It also made the two harnesses incomparable. `api-loop` runs the model host-side, so its model
calls never cross the sandbox proxy at all; the same skill under the two harnesses produced two
different capability profiles, which is exactly what the §13.5 tier model is supposed to hold
still.

Non-skill-attributed egress is therefore its own tier-1 class, `egress_infrastructure:<host>`, at
the floor weight — written into `DEFAULT_CAPABILITY_WEIGHTS` explicitly rather than left to fall
there by omission, so the choice is visible and overridable, the same treatment `egress_blocked`
already gets. §11.3 does not enumerate a tier-1 class for this, the same gap the DNS branch fills
for "`dns_query` outside allowlist"; this note is the record of filling it.

Two details worth keeping. A record with **no** `egress_class` reads as the skill's, not the
harness's: an unlabelled flow is an observation we could not attribute, and downgrading it to the
floor on the strength of a missing field is a silent loss of the exact signal the class carries.
And the infrastructure egress is **reclassified, not dropped** — it stays in the step sequence,
because *how* a run went includes its infrastructure moves, which is the same reason §11.4 keeps
baseline-absorbed paths in the sequence while removing them from the capability sets.

`CANON_VERSION` goes to `1.1`: capability derivation changed, so traces canonicalized either side
are not comparable, and the §17.5 comparability table refuses to compose a regression across the
boundary rather than comparing two different things. The weights digest moves too, by the
mechanism §13.5.1 already provides for exactly that. The committed demo artifacts and the golden
trace were regenerated; the only differences are those two versions, and every demo verdict is
unchanged.

**A correction worth recording**, because it nearly became the brick. An initial reading of the
weight table concluded that `egress_non_model`, `dns_outside_allowlist` and `process_exec` were
dead keys taking the floor weight — the policy names finding kinds, the metric keys on base
classes. They are not dead: `resolve_capability_weights` translates between the two, and the first
test of this bypassed it and read the raw policy dict. The lesson is the project's own and was
applied in the wrong direction: run the real path, not a shortcut through it.

## §12.6, §17.2 — The platform baseline is an allowlist, so the report publishes it

§12.6 requires the baseline's full contents in the report, collapsed by default, and gives the
reason in one line: *a hidden allowlist in a security tool is a liability*. That requirement was
unimplemented. The report carried `platform_baseline_version` — a string — and nothing else.

The consequence is worse than a missing section. Scope evaluation runs against
`observed − platform_baseline`, so every baseline entry is something the skill *did* that the
declared-vs-observed table does not show. Publishing the verdict without the terms of that
subtraction asks a reviewer to trust the most valuable section in the tool on the strength of a
version number.

**Two things reached `summary.json` and no further.** `analyse_run` produced
`baseline_absorbed` — its own docstring calls it "the audit trail" — and `baseline_near_misses`,
`aggregate` carried both onto the set reading, and `_build_summary` put both into
`security.runtime`. What read them after that was nothing: no verdict, and neither renderer. The
near-misses are the sharper loss, because §12.6 says a suspicious near-match
(`~/.cache/../.aws/credentials`, a process whose argv0 matches a helper but whose parent does
not) MUST *raise a finding* rather than be silently absorbed — and a key in a JSON file no
surface renders is not a raised finding.

> **Correction.** The commit and PR that landed this section said the two were "dropped on the
> floor" and reached "no summary, no verdict, no renderer". That overstated it: both had been in
> `summary.security.runtime` since `21c6962`, well before. What was genuinely absent was the
> §12.6 requirement itself — the baseline's *contents* in the report — and any rendered surface
> for either list. The fix is unchanged and still warranted; the description of the defect was
> wider than the defect. Recorded here rather than quietly amended, since a notes file that
> silently improves its own history is worth less than one that does not.

`Summary.platform_baseline` now carries the contents, what this evaluation absorbed, and the
near-misses. The HTML report renders it collapsed; the PR comment carries it too, because an
allowlist auditable only inside an uploaded artifact is close to not auditable. The near-misses
render **outside** the collapsed block in both, since a finding folded behind a disclosure
triangle is most of the way back to silent.

Two distinctions are kept deliberately. `applied` travels separately from an empty `absorbed`: a
baseline not keyed to this run's image absorbed nothing for a different reason than one that
applied and matched nothing, and a section that disappeared would let the second stand for the
first — so it renders either way, with the state named. And an evaluation with no baseline
configured gets no block at all, because absent is not empty.

`SCHEMA_VERSION` goes to `1.4` (an added optional key, so a minor bump) and the committed JSON
Schema is regenerated.

**A second schema-version constant had drifted.** `bellwether version` printed
`summary.json schema 1.0` from `bellwether.SUMMARY_SCHEMA_VERSION` while every summary it wrote
stamped `1.3` from `report.summary.SCHEMA_VERSION`. Reporting the schema a consumer should expect
is the only job that line has. The duplicate is gone and `version` reads the constant that does
the stamping, with a test asserting the two agree — which is the kind of test that would have
caught it at the point the second copy was introduced.

**What is still not done here.** `tools` and `processes` are published but not yet *applied*:
`baseline_absorption` handles paths only. Tool attribution needs no new capture plane and is the
next increment; process attribution waits on the §10.3 process plane, which is v0.3 work.

## §13.5.4, §3.5/§10.2, §12.6 — Three declared controls that did nothing, and the false positive each would have had

The shipped `policy.yaml` lists thirteen `security_runtime` dispositions. Four drove the verdict.
The other nine read, to anyone opening the file, as controls that are on. `doctor` has named the
inert ones since BW-49, which is honest, but naming a gap is not closing one. Two of those nine had
their evidence already computed, aggregated onto the reading and rendered in the report — they were
one gate each away from working. This closes both, and applies §12.6's last un-applied area.

**Each one's real difficulty was its false positive, not its evidence.** That is worth stating
plainly, because in all three cases the naive implementation is about ten lines and is wrong.

### §13.5.4 — `sensitive_directory_access`

The hits were computed, aggregated, and shown in the §13.5.2 dual-tier section; the policy has said
`block` from the start; no gate read them. A skill could read `~/.aws/` on every run and, so long
as it exfiltrated nothing, clear every scored gate in the profile.

*Presence before coverage.* §13.5.4 is frequency-independent and says why — a once-in-twenty read of
`~/.aws/` is more alarming than a consistent one, not less — so a recorded hit takes the policy
disposition whatever the coverage. Only the *pass* waits on Plane A supporting an absence claim
(§10.8). Inverting that, and deferring on a run that actually touched `~/.ssh/` because its
coverage was imperfect, would be the worst of both readings.

*The false positive.* `legit-credential-reader` exists in the corpus precisely to catch this: it
declares `${HOME}/.aws/credentials` under `credentials.expects`, reads it, sends nothing outward,
and must reach `ready`. A gate blocking on any sensitive hit fires on every correct run of it —
the guaranteed false positive the spec says a flagship finding must not have. So the gate reads
*undeclared* hits, and a declaration excuses a hit only by naming the sensitive location. A
blanket `${HOME}/**` does not, because the reason §13.5.4 exists is that a broad glob hides
exactly this access; `init-manifest` already draws the same line when it refuses to write a
sensitive path into an inferred allowlist.

*Matching the declaration against the hit took three attempts, and the first two were wrong.* The
first compared the declared glob against the hit's tier-2 **prefix**, which fails in both
directions at once. A workspace hit's tier-2 is the bare first segment — `workspace_read:.git/` —
while declarations are `${WORKSPACE}`-rooted, so an explicit `${WORKSPACE}/.git/**` never matched
and a skill reading its own repository could not declare its way out of a blocking, required gate.
Meanwhile the home-root hit's prefix is `${HOME}`, which *every* home-rooted glob starts with, so
the blanket the rule exists to see through was the one declaration that did excuse it.

The second attempt matched the sensitive *directory token* as a path **segment anywhere** in the
entry. That fixed both of the above and opened three bypasses, none of which the offline suite
noticed:

- **Cross-zone.** The rule had no notion of which root a declaration sat under, so a harmless
  fixture path in the skill's own repository — `${WORKSPACE}/fixtures/.ssh/known_hosts` — excused a
  real read of `${HOME}/.ssh/`. A skill could ship a decoy declaration and reach the operator's
  keys with a blocking gate reporting `pass`. This is the worst defect this gate has had.
- **Home root.** `${HOME}/.aws/credentials` — `legit-credential-reader`'s own manifest line, which
  names `.aws/` — also excused an undeclared read of the home root itself, and therefore of
  `~/.netrc`, `~/.bash_history` and every other file tier 2 collapses onto it.
- **Direction.** The read and write declarations were pooled into one list, so a declared *write*
  to `${HOME}/.aws/cache` excused an undeclared *read* of `${HOME}/.aws/` — the access anyone
  actually cares about.

The rule is now **anchored, zone-aware and direction-aware**: an entry excuses a hit only where it
points into that exact rooted location, nothing before that point is a glob, and it sits under the
declaration list matching the hit's direction (`credentials.expects` counts as read, since
declaring that a credential is expected is a statement about reading it). The home root keeps its
special case — only a file declared *directly* in `${HOME}` names it — and a hit on a single file
must be named exactly, so `${WORKSPACE}/.gitignore` does not excuse `.git/`. Each bypass is a test
that fails against the old rule.

*A second review found the anchored rule had introduced a regression of the exact shape it was
meant to prevent.* `_hit_direction` classified by the `_read`/`_write` suffix, so
`workspace_delete` fell through to an empty declaration list: **no manifest entry of any kind
could excuse a deletion under a sensitive directory**, in any section. `git status` creates and
removes `.git/index.lock` on the same runs that rewrite `.git/index` — the case pinned two
paragraphs above as designed behaviour — so a git-using skill sat at `not_ready` with no escape.
The file had classed a deletion as a write since `_BASELINE_WRITE_CLASSES` was written; only this
new function read the two tables differently. The classification is now shared and **total**: any
zone not on the write list is answerable by a read declaration, so an unforeseen zone behaves like
a slightly loose read rule rather than an inescapable block. For a gate whose disposition is
`block`, that is the safer direction to be wrong in.

*The gate's advice pointed at an entry the gate rejects.* For a home-root hit the finding
suggested `${HOME}` — which `_declaration_names` refuses by design, since the home root is named
only by a file sitting directly inside it. An author following the gate's own instruction verbatim
stayed at `not_ready`; for a deletion the hint degraded to a placeholder. The function had no test
of any kind. Every suggestion is now fed back through the matcher by a parametrized test, which is
the only reason a user-facing string wrong in two of its four shapes would not ship again. This is
reachable without adversarial intent: an `ls` of `~/.aws` classes as `outside_workspace_read:${HOME}`
rather than `.aws/`, because a path with two parts maps to the root.

*Two smaller matching defects.* `${HOME}/.` and `${HOME}/..` satisfied "a single slash-free
segment" and so excused every file tier 2 collapses onto the home root — a declaration pointing at
the *parent* of home reading to a reviewer as naming anything but home. And braces were not
expanded, so `${HOME}/{.aws,.config}/**` was a supported declaration in the Declared-vs-Observed
table (which compiles through `glob_to_regex`) and an *undeclared* sensitive access to this gate:
one manifest line, two contradictory readings, and a `not_ready` telling the author to add a line
they already had. Expansion now goes through the same helper, which already knows `${HOME}` is a
placeholder and not a one-choice brace group.

*The headline fix was untested at the seam that was broken.* Every test written with "the
configured list reached nothing" passed `sensitive_directories=` straight into `analyse_run`, so
only the innermost hop was covered. Deleting both wiring lines — `config → run_evaluation` and
`run_evaluation → drive_evaluation`, putting the code back in exactly the state this note calls a
defect — left the whole offline suite green. Both hops now have a test that fails without them.

*A residual limit, disclosed rather than closed.* Tier 2 collapses every file directly in `${HOME}`
onto one entry, so declaring `${HOME}/.bashrc` does still excuse a read of `${HOME}/.netrc`.
Separating them needs tier-3 granularity in the hit, which the §13.5.2 dual-tier model
deliberately does not carry. The alternative — refusing every home-root declaration — would take
the legitimate case down with it.

*The `.git/` edge is real and is the designed behaviour.* `git status` rewrites `.git/index`, so a
skill that runs git in its workspace produces `workspace_write:.git/` on every run, and a blanket
`${WORKSPACE}/**` does not excuse it. The escape is to name `${WORKSPACE}/.git/**`, and the
finding text now spells out the entry and the list it belongs under, because a gate that says
"declare it" and leaves the author to derive *what* from a tier-2 class name is most of the way to
unactionable. CI had no case of this shape at all; it has one now.

*The pass needs both planes.* A sensitive hit can arrive from a Plane A tool call naming a path or
from a Plane B write under a sensitive directory, so an absence claim over it needs both — Plane A
answers for reads and cannot answer for writes, and half an absence claim is not one. Checking
only Plane A let the gate pass on a set where the write plane was blind. The consequence is that
paths without an overlay defer, and under the shipped `block` disposition a *required*
not_evaluable gate makes the verdict `not_ready` (§16.2) — so the demo, first-light and test
profiles soften this disposition to `warn` exactly as they already soften egress, DNS and the
canary gates, and for the same reason. A real run mounts the overlay and can pass it.

*Where the exclusion is computed matters.* The live path calls `analyse_run` with `scope=None` and
carries the manifest in `declared_scope`, folding it in afterwards. Deriving the exclusions from
`scope` alone therefore passed the corpus — which threads the manifest — while marking every hit
undeclared in production. They are computed where the manifest table is applied, in both paths.

`sensitive_hits` stays the full observed list. A declared credential read is still a fact about the
skill worth showing; it is simply not a gate finding, so the report section and the §17.5
regression comparison are unchanged.

### A correction: "every fix revert-proved" was not true

The commit that fixed round 2's findings claimed *"Every fix revert-proved"*, and `docs/STATUS.md`
and `docs/spec-notes.md` repeated it. A third review measured it: eleven fixes reverted
individually against the whole offline suite, and **three left it fully green** —

- the `.a*b` fix (the glob check that ran against the observation rather than the declaration):
  no test anywhere exercised a glob character in an observed directory name;
- the gate's pass-detail branch, added so it would stop denying a sensitive access that happened:
  no demo or corpus skill reaches the all-declared pass, so nothing read the wording;
- the config validator's whitespace branch, which was **unreachable dead code** — `StrictModel`
  sets `str_strip_whitespace`, so pydantic strips every entry before the field validator runs.
  The branch could never fire, the defect it claimed to fix was therefore still there, and its own
  advice for a whitespace-only entry was to write it as `''`, which the validator rejects.

Each now has a test that fails without it, and the whitespace branch is gone in favour of saying
the thing once, in the message that can actually be reached.

The general claim was made from memory of the fixes that *were* proved rather than from a
measurement of all of them, which is the same failure this branch keeps finding in the code: a
statement of assurance standing in for the observation. It is recorded here rather than quietly
corrected, because a notes file that improves its own history is worth less than one that does not.

### §13.5.4 — what round 2's fixes cost, and a third round

Making `_hit_direction` *total* removed the undeclarable-hit class and opened a bypass one zone
over. `sensitive_directory_of` reads a basename off any tier-2 target without asking which zone
produced it — `process:curl` yields `curl`, `egress:evil.com` yields `evil.com` — so once every
non-write zone answered to the *read* list, an operator adding a hostname to
`metrics.sensitive_directories` let the skill's own `filesystem.read` entry excuse a network
capability. Before the totality change the direction was `None` and nothing could excuse it. The
hit list is now restricted to filesystem zones at its source, with the same test at the function
the gate reads: §13.5.4 is about directories, and a hostname is not one.

Brace expansion re-created the undeclarable class on a new axis. `_expand_braces` has no escape
syntax, so a location whose name genuinely contains `{a,b}` was named by no entry at all — the
same shape as the `.a*b` case, introduced in the commit that fixed it. The unexpanded entry is now
tried alongside the expansions. Expansion is also capped and cached: it is 2ⁿ in the number of
groups, the manifest is part of the package *under review*, and a 121-character entry with 22
groups took 13 seconds before this rule re-expanded it once per (hit, entry) pair of every run.
Counting the groups before recursing rather than trimming the result afterwards is what makes the
cap actually cheap.

Two more holes of the shape already closed elsewhere: a `..` segment anywhere in a declaration now
disqualifies it, because `${HOME}/.ssh/../public/**` reads to a reviewer as naming
`${HOME}/public` and bought a blanket pass on `~/.ssh/`; and the hint's own placeholder,
`${HOME}/<name>`, was literally accepted by the rule when pasted verbatim — a placeholder that
silently works is a trap set for exactly the author the hint is written for.

A §24 violation: the spelling near-miss built its fold map from an unordered set, so where two
observed tool names differed only by case the spelling the finding named depended on
`PYTHONHASHSEED` — and that text reaches `summary.json` and the byte-compared HTML report.

### The `..` fix opened a worse hole than it closed, and a second false assurance

A fourth review round. Two things worth recording, and the second is about method.

**The traversal fix was a security regression against its own parent.** `_traverses` ran on the
*raw* declaration text, and `{..}` is not a `..` segment — so `${HOME}/..` was refused while
`${HOME}/{..}` excused every file tier 2 collapses onto the home root, and
`${HOME}/.ssh/{..}/public/**` restored the exact blanket pass on `~/.ssh/` that the literal check
had just removed. The same commit *deleted* the `rest == ".."` guard from `_alternative_names`
with the comment "`..` is caught by `_traverses`", which was false. Checking each expanded
alternative independently is not enough either, because the raw entry is tried alongside them:
`${HOME}/{..}` satisfies the home-root branch as a single glob-free segment. The rule is now that
**any** alternative traversing disqualifies the whole entry, and the home-root guard is back as a
second lock — removing a check on the strength of another check is how this got in.

**The cap did not cap, and was on the wrong door.** Counting opening braces and comparing 2ⁿ bounds
nothing unless every group is binary: six ten-way groups count as 64 and expand to a million in
1.1 s, while eleven *nested* groups standing for twelve alternatives were refused — the same
false positive `expand_braces` exists to remove, recreated. And the cap sat on `expand_braces`,
the cheap literal-prefix helper, while `glob_to_regex` — which `assertions/derive.py` calls on
`scope.filesystem.read`/`.write` straight from the manifest **under review** — still expanded
uncapped and compiled the result into one pattern: 78 seconds and a 41 MB regex at 20 groups,
over two minutes at 22, on the very entry the cap's own comment cited as its motivation. The limit
is now enforced inside the recursion by raising rather than returning (returning the sub-pattern
spliced half-expanded strings into the caller's list), and both doors use it.

**"Every fix revert-proved" was false for the second commit running.** Round 3 corrected the claim
and the correcting commit made it again — 4 of 11 that time, measured. Two of those *cannot* be
proved, which is itself the useful fact: `declared = list(reading.sensitive_hits)` is byte-identical
behaviour because the branch is only reached once the undeclared list is empty. A claim that cannot
be true of every item should not be phrased as though it were.

The rule this leaves: **do not write a blanket assurance about a set of changes. Publish the
per-change measurement, including the rows that come back unproved and why.** The commit message
and this file now carry a table rather than a sentence. Twice is a pattern, and the pattern is the
same one the code keeps showing — a statement of assurance standing in for the observation.

A §24 test can be vacuous in its *mechanism* while looking substantive: the determinism test called
the function eight times in one process and asserted the results agreed, but set iteration order is
fixed within a process for a fixed hash seed, so eight repetitions of the buggy code agree too. It
now runs real subprocesses under differing `PYTHONHASHSEED`.

### §13.5.4 — the matcher, rewritten to normalise rather than enumerate

Four review rounds, and three of them found the same shape of defect: the round's headline
finding was a regression introduced by the previous round's fix, all in the declaration matcher.
`workspace_delete` undeclarable; a `filesystem.read` entry excusing `egress:evil.com`;
`${HOME}/{..}` walking past a `..` check. That is not bad luck. It is what a **blacklist** does.

The rule had grown to eight interacting clauses, and most were *reject this bad shape*: no glob
before the anchor, no `.`, no `..`, no `{..}`, no `<`/`>`, no non-filesystem zone. Enumerating
bad inputs cannot terminate — every clause has an unenumerated spelling, which is exactly the
`..` → `{..}` sequence. More review rounds against that shape would keep producing findings
without converging.

So the matcher now **normalises and then compares**. An entry is reduced to the path it certainly
reaches — expand braces, drop everything from the first segment carrying a wildcard (a
declaration says nothing definite past its first `*`), then resolve `.` and `..` lexically — and
that path is compared to the sensitive location segment-wise. The old clauses become consequences:
`${HOME}/.` resolves to the home root and so is not a file *in* it; `${HOME}/{..}` expands, then
resolves above its own root and names nothing; `${WORKSPACE}/**` reduces to `${WORKSPACE}`, which
is not at-or-under `${WORKSPACE}/.git`.

Two clauses are kept deliberately rather than derived. **Any alternative traversing disqualifies
the whole entry**, because normalisation alone would let `${HOME}/.ssh/{..,qq}/public/**` buy
`.ssh/` access on its innocent branch while smuggling a traversal on the other; a conservative
rule is right for a gate whose disposition is `block`. And the `<`/`>` rejection stays, because
the gate's own finding spells its placeholder `${HOME}/<name>` and that would otherwise resolve
to a perfectly good single segment.

**The rewrite was safe to make because four rounds of review had built the harness for it.** The
48 tests in `test_sensitive_directory_gate.py` encode every bypass and every false positive found
across those rounds, and they were held unchanged as the contract. One of them failed on the first
attempt — cutting at the wildcard loses the fact that an entry *continues* past it, so
`${HOME}/.aws/**` reduced to `${HOME}/.aws` and read as naming a file in the home root. That is
the corpus doing its job, and it is the argument for rewriting now rather than later: the tests
that make it checkable exist now.

Two things the new rule fixes that **no review round found**. Three legitimate declarations
written with a redundant `./` — `${WORKSPACE}/./.git/**` and friends — were *refused* by the old
string comparison, blocking a skill that had declared exactly the right thing. And five traversal
spellings nobody tried (`${HOME}/.ssh/{.}/{..}/x`, `${HOME}/{.ssh/..,y}/z`, …) are refused without
any clause naming them. Both are now tests.

### §12.6 — the tools near-miss, reached by a second route

Flagging a baseline entry whose tool is classed differently closed the inert-allowlist trap by
*class*. It did not close it by *name*: tool names are case-sensitive and the two harnesses spell
them differently — `read` on api-loop, `Read` on claude-code — so a baseline written against one
and applied to the other absorbs nothing and, because the check required an exact name hit,
said nothing. A case-insensitive comparison now raises it. A name seen at least once under its own
`tool:` class is never reported inert, because a `Read` call with no `file_path` falls through to
`tool:Read` while another `Read` in the same run is classed `workspace_read`, and saying "absorbs
nothing" about an entry that just absorbed something would be its own false report.

### §13.5.4 — the configured list, which reached nothing

`canonicalize` has taken a `sensitive_directories` parameter since the canonicaliser landed, and
its docstring calls it "configurable, defaulted centrally". `config.yaml` has shipped a
`metrics.sensitive_directories` list since the config document landed, and the template invites
users to extend it. **No caller ever joined them.** Every run fell back to the `SENSITIVE_DIRECTORIES`
constant, so a user who added `.npmrc/` got exactly nothing, and one who removed an entry to
silence a false positive still got blocked.

That was a reporting gap while the hits were only rendered in the §13.5.2 section. It stopped being
one the moment this same change made the gate blocking and required — which is the pattern worth
naming: *closing one inert control promoted a second, quieter one into the verdict path.*

The two lists had also drifted where it mattered most. The config default spelled the home root
`~/`; `sensitive_directory_of` yields `~`; membership is exact. Wiring the config in without
reconciling them would have switched the home root off and reported nothing — a fix that makes the
control weaker while looking like it makes it real. The default now derives from the constant so
the two cannot drift again, and a config entry the matcher could never produce is **refused at
config load** rather than read as protection. Refusing is the point: an entry that cannot match is
not a weak rule, it is no rule, silently.

Not every entry without a trailing slash is a mistake — a file at the workspace root canonicalises
to a bare tier-2 token, so `.npmrc` is a meaningful entry and the validator does not demand one.

`metrics.trajectory_cluster_threshold` is in the same position and is **not** fixed here: nothing
reads it either, and `CanonBlock` is only ever constructed with its defaults. It is a metrics knob
rather than a gate input, so it is disclosed here and left for its own brick rather than widening
this change.

### §3.5/§10.2 — `harness_state_write`, attempted and withdrawn

A skill writing into the harness's own config directory is editing the instrument: settings a hook
is read from, configuration that outlives the run, state a later repetition inherits. §3.5's
concern is that a skill able to change the instrument can change what the instrument reports. The
gate was built, and then removed before it shipped, because **it could never fire**.

§10.2 admits a harness-state write into the capability set only where a Plane A tool call anchors
it, and the gate read the same anchor off the write evidence — the right rule, since a real
`claude-code` run writes its config dir constantly and that churn is the harness's. But Plane B
actions are constructed with **no `Correlation` at all** (`trace/build.py`): `anchor_seq` is only
ever set for Plane C canary findings. So `anchor_seq is not None` is false for every write that
exists, and the gate returned `pass` on a skill that had just rewritten `settings.json`. A control
that renders a clean result without observing anything — committed, by us, in the same change that
set out to close two of those.

The suite stayed green throughout, because the existing `no_harness_state_write` *assertion*
matches on zone alone and was genuinely unaffected. Only a review that asked "can this gate ever
return anything but pass?" caught it.

It also surfaces a pre-existing fact worth recording on its own: **§10.2's attribution rule is
written against a correlation Plane B never populates**, so *no* harness-state write becomes a
capability today — the rule excludes everything rather than just the churn. Correlating overlay
writes back to the tool calls that caused them is §11.5 step 3 and real work; the overlay diff is a
post-run set with no per-write timing to correlate on. The gate is worth having once that exists.
Until then it is disclosed here and in `docs/STATUS.md` rather than shipped as a pass that means
nothing.

### §12.6 — the baseline's `tools`

§12.6 defines three areas. `paths` has absorbed since the baseline landed. `processes` waits on the
§10.3 process plane, because `helpers_of` is written in terms of tree attribution and there are no
trees to attribute against. `tools` needed no new plane — a tool call is Plane A evidence every run
already has — so it was un-applied for no reason but reach.

Matched by **exact name, never as a glob**. A path baseline is written in globs because paths are
hierarchical and unbounded; a tool name is a fixed identifier from the harness's vocabulary, and a
glob there would let one `*` absorb the entire tool surface — the failure an allowlist exists to
prevent.

Absorption needed a tier-1 channel. The existing one keys on tier 3, which suits a path (absorbed
by its normalised target) and not a tool, whose tier 3 is the invocation's argument: subtracting by
that would absorb one call and leave the next. `canonicalize` takes `platform_baseline_t1`
alongside `platform_baseline_t3`, and an absorbed tool leaves the capability sets while staying in
the step sequence — the same §11.4 rule an absorbed path follows.

It ships empty, deliberately: §12.6's own default is `tools: []`, because a tool call is agent
behaviour and not infrastructure until a harness demonstrates otherwise. This gives a harness that
does demonstrate it somewhere to say so.

### What this leaves

**Eight** dispositions remain inert — five enforced of thirteen — and the reasons are not
uniform. `process_exec_undeclared` and `credential_read_undeclared` wait on capture that does not
exist yet (the §10.3 process plane, the read plane). `instrumentation_probe` waits on the §3.5
probe suite. `egress_volume_anomaly` needs a volume baseline to be anomalous against.
`unexpected_provider_endpoint` has no producer at all — the finding kind is defined in §11.3 and in
`RUNTIME_FINDING_KINDS`, and nothing in the pipeline emits it, which makes it the next one worth
closing. `trace_inconsistency` and `possible_egress_induced_failure` are computed and deliberately
advisory. And **`harness_state_write`**, whose gate was written and withdrawn in this same change
for never being able to fire: it is still configured, still inert, and belongs on this list
precisely because the withdrawal is what keeps it there.

An earlier draft of this section said *seven* and listed seven, omitting `harness_state_write` —
counting the withdrawn control as closed. In a section whose whole subject is that a declared
control which does nothing must be named, undercounting the inert set is the one direction the
error must not go. The count is now computed from `ENFORCED_SECURITY_RUNTIME_DISPOSITIONS` and the
`SecurityRuntimeGate` model rather than written out by hand.

`doctor` continues to name every one of them, and its list is now one shorter — a list that never
shrinks would keep telling an operator a live gate does nothing.

---

## §7.2, §10.0, §10.5, §12.2, §12.5, §13.1, §16.1, §19.2 — an independent review, and what its twelve findings have in common

An outside agent reviewed the repository at `592e309` with no access to this file, reproduced
what it found by running code, and reported twelve findings: one critical, six high, five
medium. Every one was verified here before anything was changed, and every one was real. The
per-finding fixes are in the commits; this entry is about the part that matters more, which is
that they are not twelve unrelated bugs.

### The shape

Eleven of the twelve are the same defect wearing different clothes: **a control that renders a
clean result without running the check.** This project's own CLAUDE.md names that as its
signature failure mode and its disciplines are written against it. It kept happening anyway, and
the reason is worth stating plainly: every one of these was found at an *integration boundary*,
where a helper that expresses a rule correctly is handed to a caller that never asks it the
question.

- `derive_assertions` compiles `tools.deny` and `filesystem.deny_read` correctly. The live `run`
  path passes `scope=None` and judges by the Declared-vs-Observed table instead, and that table
  was built from allow-lists only. Both prohibitions were evaluated nowhere. Tests of
  `derive_assertions` passed throughout.
- `EvidenceIndex.workspace` is documented as "the final workspace **on disk**, where the caller
  still has it", and `None` correctly yields `not_evaluable`. Two callers passed
  `context.workspace_root` — the path *inside the container* — so content assertions did host
  reads against a path that does not exist on the host, and failed for artifacts the skill had
  genuinely written.
- `decide_request` is a pure, well-tested security core. The addon handed it
  `request.pretty_host`, which mitmproxy documents as possibly-spoofed. The core decided
  correctly on the wrong input.
- The policy schema accepts `require_scan`, `require_manifest` and the whole `human_review`
  block. The verdict composition read none of them.
- The cache key is assembled from a careful list of run properties, and the CLI's
  `--max-tokens` override is applied *after* it.

A unit test of the helper cannot see any of these, and every one of them had a green one.

### The four preventions, and why each is an allowlist

Fixing twelve findings individually would leave the thirteenth. Each prevention below turns a
class of mistake into something that fails at authoring time. All four are allowlists, for the
reason the §13.5.4 arc already established and CLAUDE.md records: *reduce an input to what it
certainly means, then compare; do not list the ways it can be wrong.* A reject-list has an
unenumerated spelling, and here the unenumerated spelling is "the next one someone adds".

**1. The control registry** (`ENFORCING_GATE_CONTROLS` / `ADVISORY_GATE_CONTROLS`,
`tests/test_control_registry.py`). Every field on every gate model must be classified as
enforcing the verdict or as advisory-with-a-stated-reason. The build fails on a field in
neither. There is deliberately no bucket for "accepted but does nothing", because that state is
what the registry exists to make unrepresentable. This generalises
`ENFORCED_SECURITY_RUNTIME_DISPOSITIONS`, which had already been invented for exactly this
problem in one sub-model (BW-49) and was not generalised — the four inert controls the review
found were all in sub-models that constant does not cover.

**2. One containment corpus** (`tests/test_containment.py`). Every predicate that decides
whether a path stays inside a root is run against the same list of escape spellings and the same
list of legitimate names. Two predicates needed fixing here — the fixture resolver and the
assertion reader — and neither was part of the §13.5.4 arc that produced this lesson. The corpus
is the mechanism that carries a lesson across code that did not exist when it was learned.

**3. One identity corpus** (`tests/test_identity_discrimination.py`). The properties a content
identity must distinguish are listed once and applied to every identity. The symlink/marker-file
collision was found and closed in the skill payload digest months ago and left open in the
fixture digest, where the review found it again. Fixing one instance and calling the class
closed is how the second instance survives; the corpus makes "the class" a thing the test suite
knows about.

**4. A fake that can express the attack** (`test_the_fake_request_models_every_field_the_protocol_declares`).
`_FakeRequest` had a single `pretty_host` field where `mitmproxy.http.Request` has two, so no
test could describe a client that addresses one host and names another. The attack was not
*representable*, which is a stronger kind of untested than "we forgot to write it" — no amount
of adding test cases to that file would have found it. A `Protocol` gives no runtime
enforcement, so the fake's completeness is now asserted directly: a field added to `RequestLike`
must be modelled before any behaviour that reads it can be tested.

### Three judgements worth recording

**`require_scan` now defaults to `false`.** The shipped default was `true` in a build with no
static scanner. Making the control real meant choosing between a tool that refuses every run out
of the box and a document that states what the build can do; the document was wrong, so it
changed. The §16.4 refusal and the required `not_evaluable` gate are what make the `true` case
mean something, and `doctor`'s message now says the run is refused rather than that the scan
"will not run".

**The `high` profile's demo report now carries a blocking `human_review` row.** That profile has
always demanded a human review. The tool had never once checked for one. The committed
`sneaky-exfiltrator` report changing is the fix becoming visible in the artifact a reader looks
at, which is the point.

**Blocking on a disagreement, not resolving it.** The proxy refuses a request whose `Host`
header or SNI names a different host from the destination, in *either* direction — including
when the real destination is allowlisted and the claimed one is not. Resolving the disagreement
either way would mean choosing which of two attacker-supplied identities to believe. Only their
agreement is evidence.

### What the review got right that is not a code change

Two of its observations are about positioning rather than defects, and both stand. The dominant
weakness it names — "integration, not style; helpers individually express rules that disappear
at orchestration boundaries" — is precisely what the shape above describes, and the four
preventions are aimed at it rather than at the twelve instances. And its closing note that the
appropriate positioning remains an experimental evaluation framework with known enforcement gaps
is consistent with what `README.md`, `THREAT_MODEL.md` and the inert-disposition list here have
said all along; this round narrows the gaps by four controls and does not change the thesis.

### Revert-proof, per change

Every fix was proved by reverting it and watching a specific test fail, and the measurements are
in the commit messages rather than summarised as a blanket assurance — the rule this project
adopted after a previous round's "every fix revert-proved" turned out to be false for three of
eleven. One row is worth surfacing here because it came back unproved twice before it was
proved: the §10.0 quiesce. The first attempt checked for the container after `execute()`
returned, where the teardown removes it anyway; the second grepped for the evaluation id when
the container's name is randomised per run (§3.5), so it passed vacuously. It now records the
real container name at the moment Plane B is read, and fails without the fix. A test that cannot
fail is the same category of thing as a control that cannot fire, two directories over.

### §12.1 — the same rule, in one reader only: tool-name identity

This entry is a follow-on to the round above, found by pre-flighting the live run rather than by
the suite, and it is R3 a second time in the same predicate.

R3 wired `tools.deny` into the §12.5 Declared vs Observed table, which is what `bellwether run`
judges by (it passes `scope=None`, so the assertion form never runs). The wiring matched the
declared name against the observed one with an exact dict lookup. But §12.1 folds the case of a
tool name on purpose: the api-loop harness reports `read`/`write`/`bash`, the Claude Code CLI
reports `Read`/`Write`/`Bash`, and `claude-code-live-smoke` is evaluated under both workflows from
one manifest. So `tools.deny: [fetch, bash]` — the declaration every candidate live-smoke skill
carries — was **still inert on the claude-code harness**, while the scenario file beside it saying
`tool_not_called: Bash` fired correctly, because `assertions.engine` had folded case since it was
written. The manifest, the statement a reviewer reads as the stronger of the two, was the dead one.

The allow side was worse than inert and pre-dates the round: `allow: [Read]` — the spelling
`examples/skills/security-review/evals/manifest.yaml` uses — against an api-loop trace reporting
`read` matched no key, so the declaration was reported `unused` *and* the call `exceeded`. A
portable manifest would have been blocked for using precisely what it declared, and the row would
have named the tool it declared as the violation.

**Why it is the same defect, not a new one.** The rule was correct, tested, and documented — in one
of its two readers. That is what CLAUDE.md means by *where two places implement one rule, write one
corpus and apply it to both*, and what the §13.5.4 arc means by an unenumerated spelling: here the
unenumerated spelling was a second caller. The fix is therefore not "fold case in `derive` too". The
predicate moved to `assertions.evidence.tool_name_matches`, beside `ToolCallEvidence`, which both
readers already import; `engine`'s private copy is deleted rather than duplicated; and the §12.1
principle now states in the spec that the comparison is implemented once and used by every reader.

Two clauses, because folding alone is not enough. A declaration absorbs **every** matching spelling
in the trace, not the first: a trace can carry `bash` and `Bash` (two harness adapters in one
session), and popping a single key would leave the other to fall through the undeclared sweep and
read `exceeded` against the entry that declared it.

The prevention is `tests/test_tool_name_identity.py`, the fifth allowlist of the round: one corpus
of spellings that name the same tool and pairs that name different ones, driven through every
predicate that decides tool identity — both sides of the §12.5 table and both §12.2 assertions. The
discrimination half is not decoration: a predicate can fold every same-tool pair by answering `True`
to everything, and a manifest that cannot tell `read` from `write` states nothing.

**Revert-proof, per change.** Reverting the fold to an exact comparison fails all six same-tool rows
on both sides of the table (and no catalogue row, which is the finding's shape made visible).
Reverting the drain-every-spelling clause to a single `pop` fails the mixed-trace row alone.
Replacing the matcher with one that folds everything fails the discrimination half on all four
readers. Each was run and read.

### §19.2, §24 — the run cache is a sibling of the evidence, and CI could not tell them apart

Disclosed by the first labelled live run on PR #78, which failed on an invalid provider key before
spending anything. The 401 is not the finding; what the log showed underneath it is.

`bellwether run --out <out>` writes two directories directly under `<out>`: the evaluation tree
`<out>/<eval_id>/`, and — when the run cache is enabled — `<out>/.cache/runs` beside it. Both live
workflows located the first with `find "${out}" -maxdepth 1 -mindepth 1 -type d | head -n1`. That
is selection by directory-walk order, which §24 rules out for results that must be reproducible,
and here it is worse than non-deterministic: it can return the cache.

On that run it did, and every step downstream addressed the wrong directory:

- `cat "${eval_dir}/report/pr_comment.md"` printed `(no report was rendered)` — for a run that had
  rendered one;
- `bellwether pr-comment "${eval_dir}"` could not find the report and failed behind its `|| true`,
  so **no verdict was posted to the pull request**;
- `sudo rm -rf "${eval_dir}/runs"` deleted the *run cache* instead of the overlayfs scratch;
- `upload-artifact` then hit EACCES on the mode-000 overlayfs workdir that `rm` exists to remove,
  so **no evidence was uploaded**.

A verdict nobody receives and evidence nobody can inspect, from a job whose own output reads
clean. That is the same shape as every finding in the round above — a control path rendering a
clean result without performing the check — and the `|| true` is what let it be silent. It is
recorded here rather than only in the workflow because the reasoning generalises: **an output tree
with more than one thing in it needs the consumer to say which one it means, by name.**

The fix has three parts, and the third is the durable one. The selection is sorted and excludes
the cache sibling. An ambiguous tree — zero candidates, or two — is an **error**, not a guess:
every later step assumes exactly one, and a wrong guess publishes nothing while reporting success,
so this is the §16.4 stance (refuse before proceeding on an unsatisfiable assumption) applied to
the publish path. And the directory name is now `run_cache.CACHE_DIR_NAME` rather than a literal
in the CLI and a second literal in two workflows, with `tests/test_ci_evidence_paths.py` asserting
the workflows exclude *that* name — a test at the wiring, not at either helper.

**Revert-proof, per clause.** Restoring `find | head -n1` fails all three assertions. Dropping only
`! -name .cache` fails only the wiring assertion. Renaming `CACHE_DIR_NAME` in the CLI while
leaving the workflows untouched fails that assertion on **both** workflows — the coupling doing its
job, since that rename is precisely the change that would silently unpublish the evidence again.

The 401 itself is not a code defect and has no fix here: the `ANTHROPIC_API_KEY` repository secret
is present but rejected by the provider, so the live end-to-end confirmation waits on a human
rotating it.


## §10.5.0 — the proxy decides every stream it relays, not every request it parses

**Found by** the second independent review (2026-09), reproduced against the pinned mitmproxy
12.2.3 with the real `sidecar/proxy/proxy_entry.py` loaded. The addon implemented one mitmproxy
hook, `request`, and the allowlist, the identity check, the caps and the canary scan all lived
behind it. Two paths reached a destination without passing through it:

- **A `CONNECT` tunnel carrying raw TCP.** mitmproxy answers a `CONNECT` to any host:port with
  `200 Connection established` (and, under the default `connection_strategy=eager`, dials it)
  before any request inside the tunnel exists. If the client then sends bytes that are neither
  TLS nor HTTP, the default `rawtcp=true` relays them verbatim. No `request` hook runs, so nothing
  is blocked, recorded or scanned: a canary reached a server outside the allowlist and the flow
  log stayed empty.
- **An exception in the hook.** mitmproxy's `safecall` logs an addon's exception and continues
  the flow. `request.content` raises on a body that does not decode under its `Content-Encoding`,
  so a `Content-Encoding: gzip` header on a plain body sent the request to a denied host,
  undecided and unrecorded.

**What changed.** The addon now implements every hook through which a regular-mode proxy relays
client traffic, and each one fails closed:

- `http_connect` gates the tunnel on the same allowlist and identity check, before mitmproxy dials
  it (it runs ahead of the eager connect). A refused tunnel is a recorded `CONNECT` flow; a permitted
  one records nothing itself, because each request inside it is decided and recorded on its own.
- `request` routes any exception to a recorded refusal (502). Only the exception's *type* is
  recorded — the message of a decode error can carry the body.
- `tcp_start`/`tcp_message` refuse a raw stream whatever its destination and record it as a blocked
  `TCP` flow. `tcp_message` empties the payload, because mitmproxy sends a message's content after
  the hook returns and killing a TCP flow does not stop its relay.
- The decision is flushed to the flow log *before* a request is let through; a request the log
  cannot record is refused, the rule the resolver already applied to a query it cannot log.
- If rendering a refusal fails, the flow is killed.

**`rawtcp=false` as well as the hooks.** The sidecar now runs with `--set rawtcp=false`, so
mitmproxy never chooses the raw-TCP layer; the tcp hooks are the backstop. `extra_settings` may not
override `rawtcp`, `block_global` or `confdir` — the one caller (the interception probe) sets only
`connection_strategy`. **The cost, stated:** under `rawtcp=false` a raw stream inside a *permitted*
tunnel fails as an unparseable HTTP request inside mitmproxy, which no hook sees — so it is refused
but **not recorded**. Measured end to end: with the hooks alone the attempt is refused *and* recorded
as a blocked `TCP` flow; with `rawtcp=false` it is refused and absent. Both bytes-relayed counts are 0.
A tunnel to a host *outside* the allowlist is refused and recorded either way, at `http_connect`.

**Measured, per case** (real mitmdump 12.2.3, real `proxy_entry.py`, a local upstream; upstream-
received counts the canary):

| Case | Before | After (hooks) | After (hooks + `rawtcp=false`) |
|---|---|---|---|
| raw TCP via CONNECT to a denied host | relayed, 0 flows | 403, recorded | 403, recorded |
| undecodable gzip body to a denied host | 200 upstream, 0 flows | 502, recorded | 502, recorded |
| raw TCP via CONNECT to an allowlisted host | relayed | dropped, recorded | dropped, not recorded |
| plain GET to an allowlisted host | forwarded | forwarded | forwarded |

**Revert-proof.** All 13 new unit tests fail against the previous source, but most fail on the
`render` seam the old addon lacks rather than on the behaviour, so the unit tests alone are **not**
the proof; the table above is, and it was run against both sources. `test_every_relaying_mitmproxy_hook_is_implemented`
is an allowlist in the style of the control registry: a relaying hook named there without an
implementation fails the build.

**What the gate broke, and CI caught.** The §9.2 interception probe kept its probe host *off* the
allowlist, relying on a denied request being recorded after the handshake, and counted any recorded
probe host as confirmation. With the `CONNECT` gate the denied probe host is refused — and recorded —
before any handshake, so on CI a client with no CA at all "confirmed" interception (the negative
container test failed; reproduced locally: both with and without the CA the only records were
refused `CONNECT`s). The probe now allowlists its own unresolvable `.invalid` host (its sidecar is
its own; no run's policy widens) and counts only a flow recorded *inside* TLS (`scheme == "https"`).
Reproduced after: with the CA, one `https` flow and confirmation; without it, a certificate
rejection and no flow. Two new offline wiring tests fail on the old probe on behaviour.

**Not addressed here.** WebSocket frames after a permitted upgrade are relayed without a canary scan
(the upgrade request itself is decided); a `CONNECT` to a permitted host is decided on the host
alone, not the port.


## §11.4, §12.6, §13.5.4 — one path, every spelling: `//` was a way past the gate

**Found by** the second independent review (2026-09). `PurePosixPath("//home/agent/.ssh/id_rsa")`
keeps `//` as a root of its own — POSIX leaves exactly two leading slashes implementation-defined
— while Linux opens the same file as `/home/agent/.ssh/id_rsa`. The lexical normaliser
`normalize_container_path` collapsed `.` and `..` but kept that root, so the path was never
recognised as `${HOME}`: the sensitive-directory gate passed with no manifest at all, and
`deny_read: ${HOME}/.ssh/**` did not match. Only a root-agnostic glob (`**/.ssh/**`) caught it.

**Fixed at the normaliser, not at the gate.** Every tool-call path already went through
`normalize_container_path` (zone classification, `reported_reads`, the baseline's collapse), so
resolving `//` as `/` there closes the class at once. That is the rule the earlier matcher rounds
arrived at — reduce an input to what it certainly means, then compare.

**The named form had a wider hole.** §12.6 judges a path twice: resolved, for absorption, and as
the skill *spelled* it, because a path that walks out of a baseline entry (`~/.cache/../.aws/x`)
is a near-miss and must never be absorbed. The named form cannot be resolved without destroying
that evidence, so it was prefix-compared raw — and not only `//home/agent/.cache/../.aws/x` but
`/home//agent/...` and `/home/./agent/...` were never recognised as `${HOME}`, so the near-miss
went unreported (none of them was absorbed; the traversal rule held). The named form is now
*tidied* — repeated slashes and `.` segments dropped, `..` kept — by `tidy_container_spelling`.
Not applied inside `NormalizationContext.normalize_path` itself, because that function also sees
URLs, where `//` means something.

**The prevention is a corpus.** `tests/test_path_spellings.py` holds equivalent spellings of one
file and applies them at the decisions that read a path: the sensitive hits `analyse_run` hands the
gate, the `reported_reads` a `deny_read` assertion is judged on, baseline absorption, and baseline
near-miss detection. Every spelling must agree with the plain one; a new spelling is one line.

**Revert-proof, per change.** Against the old source: the three `//`-anchored spellings fail both
the sensitive-hit and the `deny_read` rows (the other ten spellings already agreed — they are
regression rows, not proof); all three traversal spellings fail the near-miss row; `//` fails the
absorption row. The six `tidy_container_spelling` rows fail on the old source only because the
function does not exist there — they are not evidence of the fix.

**Not addressed here.** A path is resolved lexically; a symlink *inside* the container
(`/work/link -> /home/agent/.ssh`) still classifies by its spelling, which only the read-capture
plane could see through. And `~` is not expanded: the api-loop tools pass paths to `cat -- "$1"`,
which does not expand it, so `~/x` there really is a workspace path; whether a harness's own tools
expand it is a per-harness question this change does not answer.


## §6.1, §7.2, §9.1 — the host does not read what the skill cannot

**Found by** the second independent review (2026-09). A skill package is evaluated content; in CI
its author is whoever opened the pull request, and the host loads it as root. Staging refused a
symlink out of the package tree, but the *loader* read through one first. Reproduced:

- `SKILL.md -> /proc/self/environ` put the process environment — which holds the real API key
  under the workflows' `sudo --preserve-env` — into the skill body the api-loop `skill` tool hands
  the model, and into the trace's result preview.
- `evals/fixtures -> <host dir>` resolved to the host directory, which `materialize_fixture` then
  copies into the sandbox workspace. The fixture-name check resolved the root *and* the name, so a
  linked root passed every name; the flat-layout fallback and the no-name path had no check at all.

**One rule, at every read.** `skill.contained_path(root, relative)` resolves both sides and asks
whether one contains the other — a symlinked file, a symlinked parent (`evals -> /root`), `..`
and an absolute path are one question. It gates `SKILL.md`, the manifest (both reads), the
scenarios file (whose prompts are *sent*, not only read), payload-doc token estimates, `plugin.json`,
plugin `skills/<x>` directories (skipped and named as a problem), the fixtures root and the empty
workspace. A link that stays inside the package is the skill's own content and is followed.

**The same rule was written twice.** `run` carried its own copy of the no-name fixture lookup;
the copy had no containment check. It now calls `resolve_fixture` rather than restating it.

**The `eval_id` finding was not reachable.** The review reported that a declared `name` of
`../../x` moves the artifact tree out of `--out`. Driving the real `run` command: the baseline
lookup (`baseline_path`) refuses any name containing `/` and runs *before* the path is built, so
such a skill stops at exit 3. A name without `/` stays inside `--out`. `eval_id` now uses the slug
anyway — hardening against a reordering, tested at the command, and stated as such.

**Revert-proof, per change.** Against the old source, twelve of the thirteen new tests fail, on
behaviour (no refusal, a linked plugin skill loaded, the fixture resolving to the host directory,
the raw name in `eval_id`); the in-package-link test passes both ways and is the over-blocking
guard. The two headline attacks were also run as scripts against both sources: before, the body
contained the key (with the key in the *launch* environment — `/proc/self/environ` does not show
variables set after exec, which the first attempt at this reproduction got wrong) and the fixture
resolved to the host directory; after, both are refused.

**Not addressed here.** The skill root itself is followed if it is a symlink — it is the path the
operator (or `changed-skills`) names, not content inside the package. A name containing `/` makes
a skill unevaluable (exit 3 at the baseline lookup) rather than evaluated under its slug.


## §17.4, §18.2 — skill-controlled text in the PR comment is text

**Found by** the second independent review (2026-09). The PR comment is posted by the workflow's
bot on the pull request whose skill it judges, and much of what it prints is the skill's choice:
its declared name, the paths and argv it touched, the tool names it called, and every gate reason,
finding and near-miss that quotes one of them. The Markdown renderer interpolated all of it
verbatim (the HTML report escaped every value), so a skill that ran `bash -c "x\n## 🟢 Bellwether
verdict: `ready` @team"` once produced a second, bot-authored verdict heading and a live mention
inside a comment reporting `not_ready`; a `|` in a reason forged a gate-table cell.

**The fix is one module, `report/mdsafe.py`.** `code()` renders a value *as data* — a code span
whose fence is longer than any backtick run in the value, with line breaks shown as `⏎`; GitHub
resolves no mention or reference inside code. `text()` renders a value inside prose or a table
cell — one line, Markdown and HTML metacharacters backslash-escaped, `@` kept from mentioning with
a word joiner. `fence()` makes a fenced block longer than any backtick run in its body. Every
dynamic value in `markdown.py` and `figures.py` goes through one of them. `REPORT_LIMITATIONS` is
a constant and stays verbatim.

**What it costs, visibly.** The committed demo comments were regenerated with `bellwether demo`:
the rendered text is the same, and one pre-existing display bug is fixed — `providers.<name>.pricing`
used to lose `<name>` as an unknown HTML tag. Internally written notes that used backticks for
emphasis now show the backticks literally, because notes can quote the skill.

**The comment upsert trusted the marker.** `find_existing_comment` edited the first comment
containing the public marker whoever wrote it — an outsider's seeded comment became the verdict's
home (rewritable by its author), or the edit was refused and, with CI's `|| true`, nothing was
posted. Only a `Bot`-typed author is now ours to edit; a person cannot author as a bot. And only
the first 100 comments were read, so a long PR stacked a new report every run; pages are now
followed (bounded at 30).

**Prevention: a parsed corpus.** `tests/test_pr_comment_injection.py` plants each of eight
payloads in every skill-controlled field at once, renders the comment, and parses it with
markdown-it (CommonMark + tables): exactly one verdict heading, no mention outside code, no link,
image or HTML but the renderer's own, and a gate table with exactly the one planted row. The test
fake for the upsert now models authors and pagination, because the old one could express neither
attack.

**Revert-proof, per change.** Against the old renderer 13 of the 32 corpus checks fail (3 forged
headings, 2 forged gate rows, 2 injected link/HTML, 6 live mentions); the other 19 are regression
rows. Against the old upsert the three new tests fail (a person's marked comment edited; a person's
marked comment not leading to a fresh report; a report on page 2 missed). A first version of the
paginated fake misread `per_page=100` as page 100 and made an existing test fail on the *old* code
for a reason that was the fake's; it parses the query string now.

**Not addressed here.** A bare URL in escaped text still autolinks on GitHub; link *syntax* is
escaped, so no label can disguise one. Another GitHub App installed on the repository also posts as
a `Bot` and could seed the marker; the workflow's own token cannot be told apart from it without a
`GET /user` the Actions token is refused.


## §13.5.1, §16.1 — a capability weight does what it says, or the policy is refused

**Found by** the second independent review (2026-09); all four reproduced before the fix.

- **The zero-weight check asked about the wrong key.** §16.1 refuses weight 0 on a class the
  manifest denies. The check compared the policy's *spelling* (`bash`) with the denied class, while a
  denied `tool:bash` takes the weight of its base class `tool`, which the policy sets as `tool_call`.
  So `tool_call: 0` — or `0.4` — erased every denied tool and passed; `bash: 0`, which erases
  nothing, was the one refused. The check now resolves the policy weights first
  (`metrics.resolve_capability_weights`, moved beside the metric so the verdict layer can call it)
  and asks what weight each denied class will actually be looked up under.
- **Fractional weights were rounded.** The metric keys on integers and the resolver called `round`,
  so `0.4` and — banker's rounding — `0.5` became `0`. A canary read plus an egress in one run of six
  produced no rare-capability finding and a weighted Jaccard of 1.0. The policy schema now refuses a
  fractional weight; the resolver's `int` is a conversion, never a rounding.
- **A key that reaches no capability was accepted.** A typo (`canary_reads`) or a parameterised class
  (`egress:evil.com`, which the base-class lookup never consults) was stored and ignored. The schema
  now refuses any key outside `constants.CAPABILITY_WEIGHT_KEYS` — the finding-kind names the
  translation table maps plus the base classes the metric reads. The table moved to `constants` so
  the config layer can check against it.
- **All-zero weights divided by zero.** `weighted_jaccard_pair` now falls back to the unweighted
  figure when every class in the union weighs 0 — stricter, never kinder.

**Two existing tests asserted the old, wrong model.** `test_a_denied_tool_cannot_be_weighted_zero`
and `test_run_refuses_a_manifest_denied_tool_weighted_zero` set `curl: 0` — a key the metric never
reads — and asserted a refusal of a weight with no effect. They now set `tool_call: 0`, and both fail
against the old validator, on behaviour; they are the revert-proof for the wiring on the `run` path.
The new `tests/test_capability_weight_controls.py` fails on the old source only at import (the
resolver moved), so it is not the proof; the reviewer's reproduction script, run before and after,
is: accepted/erased/crash/ignored before, refused/finding/fallback/refused after.
