# Bellwether review — WP-1 through WP-4: defects to fix

Adversarial review of the sandbox/skill/config/trace layers. Three confirmed defects, all
in the sandbox layer, all reproduced directly (not inferred from tests). Fix them in
priority order. Each is marked **CONFIRMED** (executed, saw the failure) with a
reproduction and a minimal fix. Lower-severity notes and a list of what was checked and
found clean follow.

Do not change behaviour beyond what each fix describes. Where a fix adds a guard, add a
regression test that would fail without it — the existing tests passed while these bugs
were live because they asserted the wrong thing or exercised only the happy path.

---

## 1. `read_overlay_diff` hangs forever on a named pipe (FIFO) in the workspace — CONFIRMED

**Severity: high.** Trusted host-side evidence collector frozen by untrusted container output.

**Where:** `src/bellwether/sandbox/overlay.py:132` (`read_overlay_diff`), content read at
line 175. Called from `src/bellwether/sandbox/docker.py:165` (`changed_paths` →
`read_overlay_diff`).

**What is wrong.** `read_overlay_diff` walks the overlay upper directory and, for any entry
that is not a whiteout, directory, or symlink, calls `absolute.read_bytes()` with no check
that the entry is a *regular* file. A named pipe opened for reading blocks until a writer
appears; nothing writes, so the read blocks permanently. The container wall-clock timeout
(`docker.py:147`) bounds only the container process — `changed_paths` runs on the host
*after* the container exits and has **no timeout**.

**Reproduction (executed):**

```python
import os, tempfile
from pathlib import Path
from bellwether.sandbox.overlay import read_overlay_diff
upper = Path(tempfile.mkdtemp()); lower = Path(tempfile.mkdtemp())
os.mkfifo(upper / "pipe")          # mkfifo needs no capability
read_overlay_diff(upper, lower)    # never returns
```

Observed: the process hangs indefinitely (killed by an external 20s timeout, exit 124). A
skill inside the `--cap-drop=ALL` container can create the FIFO with
`mkfifo /work/<workspace>/pipe` — `mkfifo` requires no capability, so the isolation profile
does not prevent it. Unix sockets hit the same unguarded `read_bytes()` and crash it with
`ENXIO` instead of hanging. (Device nodes are not reachable: `mknod` needs `CAP_MKNOD`,
which is dropped.)

**Why it matters.** The observed process decides whether the observer ever finishes — a
direct inversion of "no observer inside the observed". Any skill, buggy or hostile, DoSes
the whole evaluation. The Docker tests miss it because every workload only touches regular
files (`tests/test_sandbox_docker.py:182`, `:203`).

**Minimal fix.** In `read_overlay_diff`, after `info = absolute.lstat()`, only call
`read_bytes()` when `stat.S_ISREG(info.st_mode)`. For a non-regular, non-whiteout special
file, emit a `PathChange` (kind `created`/`modified` via `_kind_for`) that records its
presence and mode **without opening it** — a skill creating a FIFO in the workspace is
itself worth surfacing, but it must never be `read()`.

**Regression test.** Add a `mkfifo` (and, if practical, a `socket.socket` bound to an
`AF_UNIX` path) into a temp "upper" dir and assert `read_overlay_diff` returns promptly and
reports the special file without hanging or raising.

---

## 2. A skill's frontmatter `name` flows unsanitized into the Docker `-v` mount target — CONFIRMED

**Severity: high.** Untrusted input controls the trusted docker command line.

**Where:**
- `src/bellwether/skill/frontmatter.py:59` — `name: str | None`, unconstrained.
- `src/bellwether/skill/package.py:179` — `name = frontmatter.name or root.name`, no validation.
- `src/bellwether/sandbox/staging.py:102` — `install_path=PurePosixPath(install_path) / package.name`.
- `src/bellwether/sandbox/docker.py:129` — `-v {payload.root}:{install_path}:ro`.

**What is wrong.** For a third-party skill scanned in external mode, `name` is fully
attacker-controlled and reaches the docker `-v` argument with no sanitization.
`PurePosixPath.__truediv__` *resets* on an absolute operand, so an absolute or
colon-bearing name escapes the intended install directory.

**Reproduction (executed, host + real container):**

```
name: "/etc"    -> install_path == /etc
                -> -v /tmp/.../payload:/etc:ro   (payload shadows /etc; runc fails to start)

name: "pwn:rw"  -> -v /tmp/.../payload:/home/agent/.claude/skills/pwn:rw:ro
                -> docker: invalid spec: ... too many colons  (exit 125)
```

A `name` of `/etc` relocates the read-only payload mount over an arbitrary absolute
container path; a `name` containing `:` injects extra colon-delimited fields into the `-v`
spec. Either way the skill controls, and can break, the trusted docker command line.

**Why it matters.** WP-4's premise is that "the flags *are* the security boundary" rendered
from a trusted profile (`docker.py:6-14`). A skill that can rewrite a mount target or force
`docker run` to fail breaks that: at minimum it reliably forces its own run to
`sandbox_error`/not-evaluable (a §3.5 evaluation-evasion lever), and it can shadow container
paths the harness depends on. The colon-count rejection that currently prevents defeating
`:ro` is luck, not a control.

**Minimal fix.** Validate `name` before it is ever used to build a path. Reject (or
slugify) any name containing `/`, `:`, `..`, whitespace, or control characters, and derive
the container install directory from that sanitized identifier rather than the raw
frontmatter string. Mirror the existing control-character reporting used for *file* names
(`src/bellwether/skill/digests.py:164`, `has_unusual_path_characters`).

**Regression test.** Load a skill whose frontmatter `name` is `"/etc"` and one that is
`"a:b"`; assert the derived install path stays under the intended skills directory and that
staging/argv construction refuses or neutralizes the name.

---

## 3. Declared-writable `/home/agent/.claude` is read-only in the container; `writable_paths` is dead — CONFIRMED (latent until a harness runs)

**Severity: medium-high.** A declared-writable path that isn't writable; a config field that does nothing.

**Where:**
- `src/bellwether/sandbox/isolation.py:72` — `writable_paths = ("/work", "/tmp", "/home/agent/.claude")`, never consumed.
- `src/bellwether/sandbox/docker.py:126-129` — only workspace bind, `--tmpfs` for scratch, and the read-only payload bind are emitted; `docker_flags()` emits nothing for `writable_paths`.
- `src/bellwether/config/models/config.py:51` — `SandboxConfig.writable_paths` defaults to `["/work", "/tmp"]`, dropping `/home/agent/.claude` — the two collections disagree.

**What is wrong.** With `--read-only` root fs and no mount for `/home/agent/.claude`, that
path stays read-only. Nothing reads `IsolationProfile.writable_paths` at all.

**Reproduction (executed, real container):**

```
echo w > /tmp/t                         -> tmp_ok
mkdir /home/agent/.claude/state         -> Read-only file system   (FAIL)
echo x > /home/agent/.claude/state.json -> Read-only file system   (FAIL)
```

**Why it matters.** `/home/agent/.claude` is the harness-state zone
(`src/bellwether/sandbox/zones.py:110`) — where the `claude-code` adapter (WP-17) will store
session state. Once a harness runs, every state write fails with `EROFS`, the run errors,
and "a run where the agent could not write anything reads as a skill that did nothing" —
the same failure shape as the already-fixed chown/EACCES bug. Latent only because no harness
exists yet; WP-17 is the next thing that sits on it. Note this is *not* the same as the
chown fix in `spec-notes.md §9.1 step 1`: that fixed ownership, but this path is unwritable
for a different reason (no writable mount under a read-only root).

**Minimal fix.** Have `DockerBackend.run` consume `isolation.writable_paths`: emit a
`--tmpfs` (or a host-backed writable mount) for each declared writable path that is not the
workspace, in particular `/home/agent/.claude`. Mount the read-only payload bind *after* the
writable parent so `skills/<name>` stays read-only underneath a writable
`/home/agent/.claude`. Reconcile `SandboxConfig.writable_paths` and
`IsolationProfile.writable_paths` so they cannot drift.

**Regression test.** A Docker test asserting a write to `/home/agent/.claude/` succeeds while
a write to the installed payload under it still fails.

---

## Lower-severity notes

- **`DockerBackend.command_line` is not the command that ran** — `src/bellwether/sandbox/docker.py:167`. Docstring claims "the exact command … for a human to re-run," but it omits `--network`, `--hostname`, `--name`, both `-v` mounts, the env, and `-w`. Currently unused (no caller), so no live impact — but if it is later recorded in the trace it will be a false fidelity claim. Either complete it to match `run`, or drop it until it is needed.
- **CLI `trace` command reports "not implemented … WP-3"** — `src/bellwether/cli/app.py:273` — though the ARF reader landed in WP-3. Cosmetic; consistent with there being no runner yet.
- **`pids_limit` exit reason is never produced** — `src/bellwether/sandbox/docker.py:42` (`exit_reason`) can only emit `timeout`/`oom`/`harness_error`; a pids-limit hit is misclassified as `harness_error` even though `ExitReason`/`EXIT_REASONS` distinguish it as skill-attributable. Latent classification gap; not required by WP-4's done-criteria.
- **`IsolationProfile.seccomp` is never rendered** into `docker_flags()` — `src/bellwether/sandbox/isolation.py`. Harmless today (only `"default"` is used, which Docker applies automatically), but a custom profile would be silently ignored.

---

## Checked and found clean (no change needed)

- **Determinism.** Verified directly: three digests (payload stable across `evals/` edits, changes on body edit; description isolates the description field and ignores whitespace reflow); two-materialization byte + metadata identity of fixtures; attestation-digest fixed point (record → current → stale); `SeededRng` advances per draw; canonical-JSON key sorting. All hold.
- **ARF round-trip / unknown-field preservation.** `extra="allow"` + `model_dump(by_alias=True)` round-trips unknown fields; truncation detected as incomplete (no footer ⇒ `not_evaluable`), not as a parse error.
- **Config MUSTs.** All five §21 enforced settings checked with correct permissive-value triggers; policy profile deep-merge preserves untouched gates and replaces lists (verified directly); no hard-coded model identifiers; placeholders refuse loudly.
- **`spec-notes.md` reasoning.** Each entry challenged against the code; all sound. The one incompleteness — the chown note fixes ownership but not the read-only-mount problem of finding #3 — is captured above.
- **`zones.py` escape / `staging.py` symlink check.** Lexical `..` collapse happens before classification (no traversal classifies as workspace); longest-prefix zone matching correct; symlink escape check fails closed on broken/cyclic links and refuses targets resolving outside the package root.

---

## How to reproduce / verify fixes

```
uv sync --group dev
uv run pytest -m "not docker"
uv run ruff check . && uv run mypy && uv run lint-imports
uv run python tools/language_lint.py

# container tests need a daemon and root:
sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker
```
