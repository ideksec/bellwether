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
is recorded. `openai_compatible` is refused with a clear message rather than half-built: its Chat
Completions shape needs a message translation the loop's Anthropic-shaped messages don't carry, so it
is a distinct client, not a config toggle.

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
The smoke policy kept `egress_outside_allowlist` at `warn` for this first proof: a clean
run passes regardless (an observed-clean plane is a pass, not a warn), and `warn` means a surprise flow
during the shakeout does not redden the run before the pipeline itself is trusted. `test_live_config`
guards the config against silently rotting back to proxy-off.

**Update — the follow-up landed:** both live policies now set `egress_outside_allowlist` (and
`dns_outside_allowlist`) to `block`. The benign run is confirmed clean under both harnesses (PR #65),
the §16.4 precondition verifies both planes are observed (so `block` is satisfiable, not a refusal),
and the rot tests now assert `block`. Default-deny is enforced, not merely recorded: an out-of-allowlist
flow or lookup reddens the run.

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

## §12.5, §16.2 — Declared manifest scope is enforced on the live `run` path, decoupled from the stubbed network derivations

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

Known bound, disclosed: `requires.min_bellwether_version` is not checked. Version comparison needs
an ordering rule the project has not committed to, and the one profile that sets it already
refuses on its missing capture planes, so the skip cannot produce a false start today. Tracked in
STATUS → Outstanding actions.

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
(`test_the_live_config_turns_the_controlled_resolver_on`). The smoke policy kept
`dns_outside_allowlist` at `warn` for the same shakeout reasoning as egress: a clean benign run
passes either way, and a surprise lookup warns rather than reddening the run before the resolver
pipeline is trusted live. (**Update:** both `dns_outside_allowlist` and `egress_outside_allowlist` are
now `block` in both live policies — the benign run is confirmed clean under both harnesses, the §16.4
precondition confirms both planes are observed, and rot tests assert `block`.)

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

**Known bounds, stated.** The sink container path is fixed (`/dev/bellwether-events`), a §3.5
tell to draw per run later (the hook settings already take the path). The CLI's session
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
