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
