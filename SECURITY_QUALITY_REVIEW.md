# Bellwether — end-to-end security & quality review

**Reviewed at commit:** `843fd2a` (branch `claude/codebase-security-quality-review-2q75hv`)
**Scope:** the whole `src/bellwether` package (18.3k LOC), the sidecar, the CI workflows, the two lint tools, and the docs, read against `docs/spec.md` (rev 3) and `docs/spec-notes.md`.
**Method:** eight parallel subsystem reviews plus a hands-on pass by the lead reviewer. **Every Critical/High finding in this report was independently reproduced by running code** (throwaway repros, not inspection alone), in the spirit of the project's own rule — *"a passing test is not evidence; run it."* Reachability is marked **LIVE** (reachable through a shipped code path today) or **LATENT** (correct-looking but only bites once a not-yet-wired plane/adapter lands, or requires a config/backend not shipped).

**Baseline health (all green):** the six mechanically-enforced checks (`ruff`, `ruff format`, `mypy --strict`, `lint-imports`, `language_lint`, `pin_lint`) all pass; **669 offline tests pass**; **42 docker tests pass, 3 skip** (CI-only sidecar-image builds, with honest stated reasons); output is byte-stable under `PYTHONHASHSEED=12345`; `bellwether demo` regenerates its committed reports with no diff. This is a mature, unusually disciplined codebase. The findings below are, almost without exception, the project's own signature failure mode: **a control that reads correct and has a green test, but is either not wired into the live path or asserts the wrong thing.**

---

## How to read this / recommended fix order

The single most important pattern is **"declared but not wired."** Many controls are built, unit-tested in isolation, and then never connected to `bellwether run`. A downstream agent should treat the wiring gaps (BW-02, BW-08, BW-09, BW-10, BW-12, BW-19) and the inverted/undermined gates (BW-03, BW-04, BW-05, BW-06) as the priority, because those are the ones where the tool renders a verdict that looks earned and is not.

| ID | Severity | Live? | One-line |
|----|----------|-------|----------|
| BW-01 | **Critical** | LIVE | `merkle_digest` collides a symlink with a file whose content is `symlink:<target>` → forges review attestation + cache key |
| BW-02 | **Critical** | LIVE | §21 enforced-settings refusal is absent from `run`; controls can be silently disabled and the run still emits `ready`/`conditional` |
| BW-03 | **High** | LIVE | `max_rare_capability_risk` gate is inverted — misses weight-5 caps at the default, and *tightening* it to `high` disables it entirely |
| BW-04 | **High** | LIVE | `..` path traversal bypasses `deny_read`/`file_not_read` and is under-counted as in-scope |
| BW-05 | **High** | LIVE | Plane B (filesystem) events pollute the trajectory `step_sequence`, corrupting the project's differentiating metric on ordinary runs |
| BW-06 | **High** | LIVE | Absence assertions **pass** on a `partial` plane; Plane-A absence claims never gate on coverage at all |
| BW-07 | **High** | LIVE\* | base32-encode-then-split-across-DNS-labels evades the canary scan (\*live once the resolver sidecar lands; engine is shipped) |
| BW-08 | Medium | LIVE | `SandboxConfig` (memory/cpus/pids/timeout/writable_paths/zones) is silently ignored — the container always runs a hardcoded profile |
| BW-09 | Medium | LIVE | Per-evaluation identifier randomisation (§3.5) defeated by a constant seed (`rng_seed=0`) over public coordinates |
| BW-10 | Medium | LIVE | Two configured consistency gates (`min_modal_trajectory_share`, `max_mean_edit_distance`) are never enforced |
| BW-11 | Medium | LIVE | Pocock boundary hard-coded to 3 looks; a configured look schedule silently under-corrects |
| BW-12 | Medium | LIVE | `capability_risk_weights` policy keys don't match the metric's base-class lookup, and the CLI never threads them anyway |
| BW-13 | Medium | LIVE | Per-run byte cap counts request *body* only; header/path/query bytes bypass the exfil-volume bound |
| BW-14 | Medium | LIVE | `redact_headers` keeps `user-agent`/`accept`/`content-type` verbatim → a secret in a header reaches the CI artifact, unscanned |
| BW-15 | Medium | LATENT | Credential injection uses an exact host lookup while classification uses suffix match → scoped token leaks onto the wire for provider subdomains |
| BW-16 | Medium | LIVE | Sandbox-image digest pinning is advisory-only; README/CONTRIBUTING claim it is "refused unless pinned" |
| BW-17 | Medium | LIVE | Sidecar Dockerfile `pip install`s are not hash-pinned — the key-holding component's supply chain floats |
| BW-18 | Medium | LIVE | `/etc/machine-id` pinning (a §9.2 MUST) is declared but never applied; a test asserts the profile value |
| BW-19 | Medium | LIVE | Static scan (§15) is an empty stub while `require_scan: true` (the default) has no consumer; docstring claims it was "Built in v0.1" |
| BW-20 | Medium | LIVE | Duplicate frontmatter keys are silently shadowed (last-wins) with nothing reported |
| BW-21 | Medium | LIVE | Hostile frontmatter crashes `load_skill` with an uncaught `RecursionError` |
| BW-22 | Medium | LIVE | Unbounded `read_bytes()` on every package file → a large committed file OOMs the loader |
| BW-23 | Medium | LATENT | base64 payload adjacent to alphabet noise defeats canary decoding (alignment) |
| BW-24 | Medium | LATENT | A single `preceded_by_read` flag per body downgrades a co-located non-read canary from `high` to `info` |
| BW-25 | Medium | LATENT | Canary finding `offset`/`via` is non-deterministic across `PYTHONHASHSEED` (§24 violation) |
| BW-26 | Medium | LATENT | Epoch anchoring assumes monotonic spine timestamps; `bisect` misassigns events when they aren't |
| BW-27 | Low/Med | LATENT | `_norm_host` misparses a `userinfo@` authority (`evil.com` classifies as the provider) |
| BW-28 | Low | LIVE | `language_lint` misses `guarantee`/`prove`/`ensure`/`vouch` despite CLAUDE.md claiming they're banned |
| BW-29 | Low | LIVE | `pin_lint` doesn't cover `docker run`, GitHub Actions `container:`, or `services:` image refs |
| BW-30 | Low | LIVE | `GIT_SSL_CAINFO` missing from the §9.2 CA mechanism table; a subset-assertion test can't catch it |
| BW-31 | Low | LATENT | Real key / API key exposed by default dataclass `repr` (`ProxyDecision`, `AnthropicClient`) |
| BW-32 | Low | LATENT | Injection's `_AUTH_HEADERS` set is provider-incomplete (`x-goog-api-key` never injected) |
| BW-33 | Low | LIVE | `interception_confirmed` normalises recorded hosts but not `probe_host` (fail-closed) |
| BW-34 | Low | LIVE | `changed-skills` attributes a `../`-prefixed path to a `SKILL.md` outside the repo root |
| BW-35 | Low | LATENT | `IsolationProfile.violations()` doesn't report a weakened `seccomp` (or unbounded memory/cpus/pids) |
| BW-36 | Low | LIVE | Untrusted skill can exhaust host disk / collector memory (no tmpfs `size=`, unbounded `rglob`) |
| BW-37 | Low | LIVE | Scenario `env` (§7.2) has no delivery path into the container — env-var canaries are untestable |
| BW-38 | Low | LIVE | `constants.EXIT_REASONS` is dead code, wrong vs §12.7, and contradicts `results.py` |
| BW-39 | Low | LATENT | Windowed canary scan is ~4 s/MB with no input-size bound → CPU DoS on large bodies |
| BW-40 | Low | LIVE | `_norm_host` accepts odd spellings (leading-dot subdomain, bracket strip, non-numeric "port") |
| BW-41 | Low | LATENT | `compute_bci` silently drops a component that has a value but no matching weight |
| BW-42 | Low | LATENT | Trajectory single-linkage clustering can chain genuinely-different runs into one cluster |
| BW-43 | Low | LATENT | Triple-nested encoding is not decoded (matches the `nest=1` docstring) |
| BW-44 | Low | LATENT | Billion-laughs alias DAG in frontmatter OOMs `canonical_json` once unknown-fields are serialised |
| BW-45 | Info | LIVE | Machinery exclusion uses a case-sensitive `startswith("evals/")` (fail-closed via the allowlist) |

\* BW-07: the detection engine is shipped and wired to DNS today; the resolver *sidecar* that would make the covert channel reachable is the next brick, so the evasion is real now in the delivered logic and becomes end-to-end once WP-15's container half lands.

---

# Critical

## BW-01 — `merkle_digest` collides a symlink with a file whose content is `symlink:<target>` (LIVE)
- **Where:** `src/bellwether/skill/digests.py:98-114` (`_hash_one` hashes a symlink as `stable_hash_bytes(f"symlink:{target}")`) and `:143-146` (`merkle_digest` feeds only `path` + `sha256`, never the `is_symlink` discriminator).
- **Category:** security / integrity.
- **Status:** **CONFIRMED by repro.** Two materially different packages produce byte-identical digests:
  - Package A: `run.sh` is a **regular file** whose content is the 17 bytes `symlink:helper.sh`.
  - Package B: `run.sh` is a **real symlink** → `helper.sh`.
  - Both yield `run.sh` `sha256:d691e566…` and `merkle_digest = sha256:5f913f12…` — identical.
- **Why it matters:** this digest is `package_digest` (which **binds the human review attestation**, §6.3) and `payload_digest` (the **run-cache key**, §19.2). A collision means "what a reviewer approved" and "what runs" can differ while the digest says they're the same — the exact integrity property the v1→v2 length-prefixing was introduced to protect (`DIGEST_FORMAT` comment: *"a forgeable `package_digest` is a forgeable review attestation and a forgeable cache key… an integrity property, not a formatting preference"*). v2 closed the path/sha field-boundary hole but left the **leaf-type** hole open: there is no domain separation between a file-content leaf and a symlink-target leaf.
- **Failure scenario:** a reviewer approves a package where `x` is an innocuous text file containing `symlink:./helper.sh`; its digest is recorded as `current`. The file is swapped for a real symlink `x → ./helper.sh` (which the container's tools resolve and follow at runtime); `review_state()` still returns `current`, and a prior cached `ready` verdict keyed on `payload_digest` is served without re-running.
- **Fix:** feed a per-record type discriminator into `merkle_digest`'s preimage before the path, e.g. `_feed(hasher, b"symlink" if record.is_symlink else b"file")`, and bump `DIGEST_FORMAT` to `/3`. Add a test asserting `merkle_digest(symlink→X) != merkle_digest(file containing "symlink:X")` — the current `test_a_symlink_is_hashed_not_followed` asserts the record fields but never that the two digests differ.
- **Repro:** `scratchpad/verify_digest_collision.py`.

## BW-02 — §21 enforced-settings refusal is absent from `run` (LIVE)
- **Where:** detection exists at `src/bellwether/config/models/config.py:283` (`enforced_setting_violations`) and is consumed **only** in `doctor` (`src/bellwether/cli/app.py:175,180`). `run` (`cli/app.py:242`) and `run_evaluation` (`cli/run.py:60`) never call it.
- **Category:** security / spec-divergence.
- **Status:** **CONFIRMED by repro.** A config that disables all five §21-enforced settings (`egress.scan_model_api_bodies=false`, `egress.deployment=inprocess`, `dns.mode=system`, `canaries.redact_at_capture=false`, `canaries.randomize_markers=false`) is correctly detected by the model, but driving it through the real `run_evaluation` under `profile_override="medium"` (above `low`) returns a verdict with **exit 0** and no critical finding in `summary.json`. A repo-wide grep confirms the only call sites are inside `doctor`.
- **Why it matters:** `THREAT_MODEL.md:106` and spec §21 present this as an **active guarantee**: these settings *"cannot be disabled without Bellwether emitting a `critical` configuration finding and refusing to run above the `low` profile."* That guarantee does not exist at run time. The shipped workflow (`.github/workflows/bellwether.yml:105`) invokes `bellwether run` directly and **never runs `doctor`**, so §21 is enforced nowhere in the live pipeline. The project already treats a checked-in `config.yaml` as attacker-influenceable on a PR (it is the stated reason `live_client._require_trusted_anthropic_endpoint` pins `base_url`) — the §21 controls have no equivalent guard. `STATUS.md` acknowledges the gap internally, but the user-facing threat model does not.
- **Failure scenario:** a PR weakens `.bellwether/config.yaml` (canary redaction off, DNS uncontrolled, body-scanning off) and changes a skill; a maintainer adds the `bellwether-run` label expecting Bellwether's controls to be active; the run executes with them disabled and can still post `ready`/`conditional`.
- **Fix:** in `run_evaluation`, immediately after `resolve_run`, compute `config.enforced_setting_violations()`, surface them as a `critical` configuration finding in the summary, and raise `BellwetherError` (→ exit 3) unless `resolved.profile_name == "low"`. Add `test_run_refuses_a_disabled_enforced_setting`.
- **Repro:** `scratchpad/self_enforced.py` (and the config-review agent's `scratchpad/cfg_enforced_settings_gap.py`, which drives the full `run_evaluation`).
- **Note:** ranked Critical because it defeats the tool's core promise (a verdict that looks earned while the exfil/covert-channel defences are off) through an attacker-influenceable input; a reasonable reviewer could rate it High given the label/PR-access precondition.

---

# High

## BW-03 — `max_rare_capability_risk` gate is inverted (LIVE)
- **Where:** `src/bellwether/cli/orchestrator.py:499-511` (`_rare_risk`) and `:577-581` (`_consistency_result`); `_RISK_ORDER` at `:409`.
- **Category:** security / correctness — a security gate that fails open.
- **Status:** **CONFIRMED by repro** (truth table against the real functions). Spec §13.5.2 (lines 2190-2194) is explicit: a rare (<100% of runs) tier-1 capability blocks when its weight ≥ the configured threshold, `low → ≥10, medium → ≥5, high → ≥3` — so **raising the knob must make the gate stricter.** The code does the opposite:

  | configured | code blocks weight ≥ | spec blocks weight ≥ |
  |---|---|---|
  | low | 5 (over-blocks) | 10 |
  | **medium (shipped default)** | **10 — misses `process:*` and `outside_workspace_write` (weight 5)** | 5 |
  | high / critical | **nothing — gate is dead** | 3 |

  Root cause: `_rare_risk` maps weight→band (`high≥10, medium≥5, else low`), then `_consistency_result` blocks only when `_RISK_ORDER[band] > _RISK_ORDER[config]` (strict `>`), so the configured severity acts as a *floor the observation must exceed* instead of a *threshold the weight must meet.*
- **Failure scenario:** a skill reads `~/.ssh/id_ed25519` via a subprocess (`process:cat`, weight 5) in 1 of 20 runs. At the shipped `medium` default the gate does not block → the run can be `ready`. An operator who *hardens* to `max_rare_capability_risk: high` disables the gate for everything, including a rare `canary_read`/`egress:evil.com` (weight 10). This is the only frequency-independent rare-capability protection currently wired into the orchestrator (§13.5.1.1 designates it as *the* mechanism Jaccard provably cannot replace).
- **Fix:** map the configured severity directly to the spec weight threshold (`{low:10, medium:5, high:3, critical:3}`) and block when `any(f.weight >= threshold for rare finding f)`. Add a test that exercises the *blocking* path with a real severity — `test_a_rare_high_risk_capability_blocks_at_every_look` asserts membership of `rare_findings` but never that the gate blocks, so it passes today while the gate is broken.
- **Repro:** `scratchpad/verify_rare_gate.py`.

## BW-04 — `..` traversal bypasses `deny_read`/`file_not_read` and is under-counted as in-scope (LIVE)
- **Where:** `src/bellwether/assertions/evidence.py:183-185` (`_normalize_tool_path` does placeholder substitution but does **not** collapse `..`), consumed by `assertions/derive.py:161` and the `file_read`/`file_not_read` evaluators in `assertions/engine.py`. `capability_for` (the heatmap path) *does* collapse `..`, so the two derivations of "what the skill read" disagree.
- **Category:** security / correctness.
- **Status:** **CONFIRMED by repro.** With glob→regex `fullmatch` (the actual matcher):
  - `deny_read ${WORKSPACE}/.env`: a direct read matches (caught), but `${WORKSPACE}/sub/../.env` (same file) → `fullmatch` **False** → the `file_not_read` assertion **passes** (missed).
  - scope `${WORKSPACE}/**` matches `${WORKSPACE}/../../../../etc/shadow` → **True** → a workspace-escape read is marked **in-scope** (`supported`), so `scope_exceeded` is empty and no violation is raised — while the capability heatmap correctly reports `outside_workspace_read → /etc/shadow`. The two headline security outputs contradict each other.
- **Failure scenario:** a third-party skill declares a tidy workspace-only scope, then reads `~/.aws/credentials` as `../../home/agent/.aws/credentials`, or evades a `deny_read` with an `x/../secret` spelling; the scope table says "in scope," the assertion says "pass," and the escape ships as `ready`. (The `file_read`/`file_not_read` assertions are reachable via scenario suites today; the manifest-scope table is behind `scope=None` in the current live driver, so that half becomes live when declared scope is wired.)
- **Fix:** collapse `..` before scope/assertion matching — have `_normalize_tool_path` run the path through `normalize_container_path` (as `capability_for` already does) so `reported_reads` carries the *reached* path. Add a traversal test to `test_assertions.py`.
- **Repro:** `scratchpad/verify_traversal.py`.

## BW-05 — Plane B (filesystem) events pollute the trajectory `step_sequence` (LIVE)
- **Where:** `src/bellwether/trace/canonical.py:125-128` — the `for action in ordered` loop appends a step signature for **every** action, with no filter against `canon.traj_planes` (which is `["A","C","D","E"]`; filesystem = B is deliberately excluded).
- **Category:** correctness / spec-divergence — corrupts the differentiating metric (the thing CONTRIBUTING warns "silently corrupts the project's differentiating metric… everything built on top will look plausible").
- **Status:** **CONFIRMED by inspection + agent repro.** §11.6 and the code's own docstrings state Plane B must not contribute to the trajectory at overlay-diff fidelity (*"identical timestamps are how a set says it is a set"*); capability *sets* should still include filesystem writes (they do). But `step_sequence` gets a `file_write` step per write. Two runs with identical Plane-A behaviour that persist 2 vs 9 output files (ordinary task variance) produce `distinct_clusters=2, modal_cluster_share=0.5`; with Plane B excluded as intended they are 1 cluster, distance 0.0. `modal_cluster_share` is a BCI component, so a perfectly consistent skill is scored inconsistent whenever its output-file count tracks its input.
- **Fix:** in the loop, append to `steps` only when the action's plane letter is in `canon.traj_planes`; leave the capability-set accumulation unchanged. Add a test asserting `file_write` steps are absent from `step_sequence` while `workspace_write` remains in `caps_t1`.
- **Repro:** agent `scratchpad/trace_planeB_pollution.py` (structure confirmed by lead reviewer against `canonical.py:125-140`).

## BW-06 — Absence assertions pass on a `partial` plane; Plane-A absence never gates on coverage (LIVE)
- **Where:** `src/bellwether/trace/models.py:218-219` (`is_usable()` returns True for `partial`) and the Plane-A evaluators in `assertions/engine.py` (`_tool_not_called`, `_skill_activated`, `_other_skill_activated`) which never call `index.plane_reason("harness_events")`.
- **Category:** security / coverage-honesty — the core thesis ("a missing plane must read as 'unavailable because X', never as a clean run").
- **Status:** **CONFIRMED by inspection.** `is_usable` returns True for `{full, partial, overlay_diff}`, so `plane_reason` returns `None` for a `partial` plane and every filesystem absence assertion proceeds — `no_harness_state_write`/`no_write_outside` **pass** on a `filesystem_writes: partial` run whose harness-state zone was never observed. Separately, no assertion consults the harness-events coverage, so `tool_not_called("WebFetch")`/`skill_activated(false)` **pass** on a `harness_events: partial` Plane A. Because the event sink drops *later* events at its byte cap (`capture/sink.py`), a skill can emit innocuous events to fill the cap, then make its `WebFetch` call and have it dropped — an evaluation-evasion lever that also silently bypasses a manifest `tools.deny`.
- **Fix:** treat `partial` as *not usable for absence claims* (split "usable for presence" from "usable for absence"), and gate the Plane-A absence evaluators on `plane_reason("harness_events")`, returning `not_evaluable` with the coverage reason. Note `test_a_degraded_write_plane_blocks_write_assertions` only exercises `unavailable`, giving false confidence that "degraded blocks" — `partial` does not.
- **Repro:** agent `scratchpad/trace_partial_plane.py`; `is_usable` confirmed by lead reviewer.

## BW-07 — base32-encode-then-split-across-DNS-labels evades the canary scan (LIVE once resolver lands)
- **Where:** `src/bellwether/capture/canary.py:293-295` (`scan_for_canaries` computes `decoded_forms(text)` first, then adds `strip_dns_labels(form)` of each form — it never decodes the *de-dotted* form), reached from `dns.py:120` (`scan_query_for_canaries(..., is_dns=True)`).
- **Category:** security / detection false-negative — in the exact channel the DNS plane exists to police.
- **Status:** **CONFIRMED by repro** (independently by two reviewers). base32-encode the whole 40-char marker once, split the ciphertext across DNS labels: 8-char-aligned labels, 4-char labels, and 2-char labels **all return 0 findings**; an even-thirds split was caught only by luck (one label happened to base32-decode in isolation to a ≥12-char marker window). The decode step (§10.4.2 step 1) and the label-strip step (step 4) never compose: after stripping you have contiguous base32, but nothing base32-decodes it. This is *not* the documented `encoded-chunked-thief` limit (that encodes each chunk independently) — it is encode-once-then-chunk, which the de-dot step explicitly claims to handle. The shipped `test_a_dns_payload_split_across_labels_is_found` only covers a **plaintext** split, giving false confidence.
- **Reachability:** the controlled resolver's default-deny still *blocks* the egress once its sidecar lands (WP-15), so this is a **detection/evidence** miss rather than live data loss — but the plane's entire product is the `critical canary_leak` finding, which is silently absent, so a malicious skill's DNS-exfil attempt goes unreported in the verdict.
- **Fix:** for DNS, also feed the reassembled form back through the decoders (`decoded_forms(strip_dns_labels(text))`), handling the attacker-domain suffix glued onto the base32 run; add an **encoded** (not plaintext) label-split regression to `test_dns.py`.
- **Repro:** `scratchpad/verify_dns2.py`, `scratchpad/verify_net.py`.

---

# Medium

## BW-08 — `SandboxConfig` isolation/resource/zone settings are silently ignored (LIVE)
- **Where:** `src/bellwether/cli/execution.py:158` calls `prepare_sandbox(self.package, self.fixture, run_dir, rng=rng)` with no `isolation=`/`zones=`/`randomize_identifiers=`; the only production `IsolationProfile()` is the hardcoded default at `sandbox/session.py:125`.
- **Status:** CONFIRMED by grep. `SandboxConfig.image` is wired (via `run.py`); `memory`, `cpus`, `pids_limit`, `timeout_seconds`, `writable_paths`, `randomize_identifiers`, and custom `ZoneConfig` paths are not — the executor builds `IsolationProfile()`/`ZoneMap()` from defaults every run.
- **Impact:** a user who sets `sandbox.timeout_seconds: 1800` for a heavy scenario is ignored and the container is killed at 900 s → scored `timeout` → reads as skill instability, with no operator remedy. Same for raised memory/pids on a Node-heavy harness. This is the same bug class as the already-fixed `writable_paths` gap (spec-notes §9.2), one layer up at the config→profile boundary.
- **Fix:** add `SandboxConfig.to_isolation()`/`to_zone_map()`, carry them on `SandboxRunExecutor`, and pass them into `prepare_sandbox`. Test that a non-default config value reaches `docker_flags()`.

## BW-09 — Per-evaluation identifier randomisation defeated by a constant seed (LIVE)
- **Where:** `src/bellwether/cli/execution.py:146` (`rng_seed: int = 0`) and `:157` (`SeededRng(self.rng_seed, f"{plan.scenario.id}/{plan.target.slug}/{plan.repetition}")`); `run.py:160` constructs `SandboxRunExecutor` without `rng_seed`.
- **Status:** CONFIRMED by grep — no `rng_seed=` is ever passed; the derivation string is built purely from public coordinates (`scenario.id`, `target.slug`, `repetition`) with no `eval_id`.
- **Impact:** the workspace slug, hostname (`$HOSTNAME`, readable inside), and container name are a deterministic function of open-source-known inputs, **identical across every evaluation** of the same coordinates — the §3.5 evaluation-detection attack the randomisation exists to stop ("`if hostname in {precomputed}: behave benignly`"). Secondary and certain: a constant `container_name` collides when two evaluations of the same skill run concurrently (CI re-trigger), failing the second `docker run` as `sandbox_error`.
- **Fix:** derive the per-evaluation seed from a random value recorded in the run header (the `canary_seed` pattern — random per eval, recorded for reproducibility) and mix `eval_id` into the stream; do not ship a constant default.

## BW-10 — Two configured consistency gates are never enforced (LIVE)
- **Where:** `min_modal_trajectory_share` and `max_mean_edit_distance` are defined at `config/models/policy.py:130-131` and have **no consumers anywhere in `src/`** (grep-confirmed). `_consistency_result` (`orchestrator.py:566-592`) checks only `min_bci`, weighted Jaccard, and the (broken, BW-03) rare-risk gate; `mean_pairwise_distance` is never even stored on `SetReading`.
- **Status:** CONFIRMED by grep. §13.4/§16.1: *"Gate on modal cluster share and mean edit distance, not on entropy."*
- **Impact:** a skill whose trajectory fans into 5 distinct clusters (modal share 0.2, mean edit distance 0.785) clears the consistency gate as long as BCI and weighted Jaccard pass — the dedicated trajectory gates that exist to catch exactly this never fire. (This compounds BW-42.)
- **Fix:** store `mean_pairwise_distance` on `SetReading` and add both comparisons to `_consistency_result`, guarding the `None`-at-N=1 case.

## BW-11 — Pocock boundary hard-coded to 3 looks (LIVE)
- **Where:** `src/bellwether/metrics/sequential.py:95` and `metrics/outcome.py:126-134` both call `wilson_interval(..., z=POCOCK_BOUNDARY_Z[3])` unconditionally; the policy's validated `boundary_z` is never threaded in.
- **Status:** CONFIRMED (agent repro). `MatrixSpec` accepts other look schedules and validates `boundary_z` against `POCOCK_BOUNDARY_Z[len(looks)]`, but the gate always uses 2.289.
- **Impact:** a policy with `looks: [6,12,16,20]` (correct `boundary_z: 2.361`) is scored with z=2.289 — the interval is too narrow, the multiple-looks correction under-applied, and the gate passes skills it should escalate. The default 3-look config is correct, so this only bites custom schedules, silently.
- **Fix:** pass `boundary_z`/`looks` from `profile.matrix` into `decide_at_look`/`summarise_outcomes`.

## BW-12 — `capability_risk_weights` policy keys don't match the metric lookup, and aren't threaded (LIVE)
- **Where:** policy default keys at `config/models/policy.py:185-199` (`egress_non_model`, `dns_outside_allowlist`, `process_exec`, …) vs the metric lookup in `metrics/capability.py:53` (`base = tier1.split(":",1)[0]` → `egress`, `process`, `dns_query`). `cli/run.py:111` calls `drive_evaluation(...)` without `weights=`.
- **Status:** CONFIRMED by grep. The two shipped default tables use different key conventions, no resolver translates between them, and the CLI never passes the policy weights at all (so defaults are used today; the bug is latent-but-real: any attempt to honour a policy override with the obvious wiring silently collapses `egress:*` 10→1, `process:*` 5→1, `dns_query` 10→1).
- **Impact:** operator weight overrides are ignored; if wired naively, the highest-risk classes drop to the floor — a ~5× under-penalty on exactly the classes the weighting exists to catch. `verdict/validation.py:50-55`'s deny-weight-0 check inherits the same mismatch.
- **Fix:** add the policy→base-class resolver the spec-notes §13.5.1 "already-resolved weights" note assumes, apply it at policy load, and thread the result through `drive_evaluation(weights=...)`.

## BW-13 — Per-run byte cap counts request body only (LIVE)
- **Where:** `src/bellwether/capture/proxy_core.py:98-101` (`caps.would_exceed(len(body))`), `capture/egress.py:169-179` (`CapLedger`). Headers and the URL path/query are not counted, and `upstream = dict(headers)` (`proxy_core.py:105`) forwards all headers.
- **Status:** CONFIRMED (agent repro). With `max_request_bytes=10`, a request carrying a 100 KB header and a 5 KB query is forwarded; the ledger charges only the body bytes.
- **Impact:** §10.5.1's residual-channel volume bound is defeated for any *permitted* destination (the model host, harness infra, an operator allowlist entry) — a skill moves unbounded volume via headers/query without tripping the byte budget. The request-*count* cap still bounds the number of requests, so this is the byte budget specifically.
- **Fix:** charge the cap for the full serialised request size (request line + headers + body), or at least add header and path bytes.

## BW-14 — `redact_headers` keeps free-text headers verbatim; headers are unscanned (LIVE)
- **Where:** `src/bellwether/capture/egress.py:53-64` (`DEFAULT_HEADER_ALLOWLIST` keeps `user-agent`, `accept`, `content-type` verbatim) and `redact_headers:182-193`; no canary scan covers header values.
- **Status:** CONFIRMED (agent repro). A secret placed in `User-Agent` survives into `EgressFlow.request_headers` → the ARF artifact uploaded to CI (which the PR author can download). Per §10.4.1 a canary in a header to a non-model host is a `critical canary_leak`, but nothing scans header values (canary scanning is wired only to DNS today).
- **Impact:** a header is simultaneously **uncounted** (BW-13), **kept verbatim** if it's on the name-allowlist, and **unscanned** — a three-way blind spot for header-based exfil to an allowlisted host. (For canaries specifically the teardown pass is a partial net, but not for the detection finding.)
- **Fix:** drop `user-agent`/`accept` from the verbatim set (or cap/scan their values), and route kept header values through the canary scanner when egress scanning lands.

## BW-15 — Injection uses exact host lookup while classification uses suffix match (LATENT)
- **Where:** `src/bellwether/capture/proxy_core.py:107` (`provider = provider_of_host.get(flow.host)`, an exact dict lookup) vs `capture/egress.py:77-88,118-122` (label-boundary suffix matching for classification/allowlisting).
- **Status:** CONFIRMED by repro. `eu.api.anthropic.com` with `provider_endpoints={"api.anthropic.com"}` classifies `model_api` and is permitted, but `provider_of_host.get("eu.api.anthropic.com")` is `None` → **no injection** → the worthless scoped token goes out on the wire instead of the real key.
- **Impact:** **no real-key leak** (only the skill-already-known scoped token is forwarded), and injection is dead in production today (`run.py:209` wires an empty broker; `provider_of_host` is always `{}` for `api-loop`). It becomes a silent auth failure the moment the `claude-code` adapter wires `provider_of_host` — spec-notes §10.5.1 names this exact "injection silently fails, looks like a broken skill" mode as the thing the fidelity tests guard, and the subdomain case reintroduces it untested.
- **Fix:** resolve the injection provider with the same label-boundary matcher used for classification, or assert at wiring time that `provider_of_host` keys are `_norm_host`-normalised and that subdomains are enumerated.
- **Repro:** `scratchpad/verify_net.py`.

## BW-16 — Sandbox-image digest pinning is advisory-only, not "refused" (LIVE)
- **Where:** `src/bellwether/config/models/config.py:337-349` — both `sandbox.image` and `egress.image` digest checks live in `advisories()` (non-blocking). No hard enforcement exists anywhere; `run` never calls `advisories()`.
- **Status:** CONFIRMED by grep. README (§Development) and CONTRIBUTING §5 both state the production sandbox image is *"refused unless pinned by digest"* / *"enforced by config validation."* It is not — it is a note that only `doctor` prints, and `run` proceeds silently with a moving-tag image.
- **Impact:** a doc-vs-code divergence in a project whose thesis is "what you review is what runs"; a moving-tag sandbox image makes two evaluations non-comparable with no warning at run time.
- **Fix:** either enforce the digest requirement in `run` above `low` (matching the docs), or correct README/CONTRIBUTING to say it is advisory. Note `examples/live/config.yaml:46` intentionally uses the moving tag `bw-proxy-sidecar:live`, so the intended behaviour really is advisory — the docs are what's wrong.

## BW-17 — Sidecar Dockerfile `pip install`s are not hash-pinned (LIVE)
- **Where:** `sidecar/proxy/Dockerfile:14` (`pip install mitmproxy==12.2.3`) and `:21` (`pip install /app`) — no `--require-hashes`.
- **Status:** CONFIRMED by inspection.
- **Impact:** the recording-proxy sidecar is the component that **holds the real API key** (`sidecar_real_key_env`) and performs credential injection, yet its Python dependency closure (mitmproxy's transitive deps, and Bellwether's own runtime deps) is resolved unpinned at build time — diverging from the `uv.lock` hash-pinning discipline the project enforces for the main package and applies its own `pin_lint` to elsewhere. The base image is digest-pinned and mitmproxy is version-exact, so the exposure is the transitive closure.
- **Fix:** build the sidecar's Python environment from a hash-pinned lock (e.g. `uv export --frozen` → `pip install --require-hashes`), or install Bellwether + mitmproxy from the same locked set.

## BW-18 — `/etc/machine-id` pinning declared but never applied (LIVE)
- **Where:** `sandbox/isolation.py:40` (`machine_id` field) is emitted by nothing; `sandbox/session.py:85-93` (`environment()`) delivers TZ/LANG/LC_ALL/HOSTNAME/HOME only, and there is no sandbox-image Dockerfile in the repo to bake it in.
- **Status:** CONFIRMED (agent repro — `machine-id` in no env var, argv token, or bind mount). §9.2 lists `/etc/machine-id` as a MUST-pin.
- **Impact:** a systemd-seeded tool derives a per-boot identifier that varies run-to-run (reads as skill nondeterminism, the exact leak §9.2 names) or a constant image machine-id becomes a §3.5 tell. `test_sandbox_host_side.py:508` asserts the *profile value* (`machine_id == "0"*32`), giving false comfort that the control is enforced.
- **Fix:** bind a host file at `/etc/machine-id` (or bake it into the sandbox image) and add a container test asserting the value *inside* the container; or drop the field and document that the image owns it.

## BW-19 — Static scan (§15) is an empty stub while `require_scan: true` has no consumer (LIVE)
- **Where:** `src/bellwether/scan/__init__.py` is 18 lines with **0 functions** and `__all__ = []`, its docstring claiming it was "Built in v0.1"; `require_scan: bool = True` (`policy.py:77`) and the template default have **no consumer** (grep-confirmed).
- **Status:** CONFIRMED by grep. None of §15's checks (instruction manipulation, base64/zero-width/homoglyph obfuscation, fetch-and-exec, credential patterns, the §3.5 `instrumentation_probe` at `high`) exist.
- **Impact:** the scanner itself is honestly deferred to v0.2 (spec §25), so the *missing code* is expected — but two things are dishonest: a policy setting `require_scan: true` gets **silent no-op** enforcement rather than a `not_evaluable`/"scan unavailable" gate, and the module docstring asserts it exists. This is the "a claim that cannot be evaluated is reported `not_evaluable`, never silently passed" rule, violated for Gate 0.
- **Fix:** until the scanner lands, treat a required-but-absent scan as `not_evaluable` ("static scan unavailable — not built"), and correct the docstring.

## BW-20 — Duplicate frontmatter keys are silently shadowed (LIVE)
- **Where:** `src/bellwether/skill/frontmatter.py:129` (`yaml.safe_load`; PyYAML keeps the last of a duplicated key) — no de-dup check anywhere.
- **Status:** CONFIRMED by repro (no problem reported for a doubled `description:`/`allowed-tools:`).
- **Impact:** a human reviewer reading top-to-bottom sees the first (benign) `description`/`allowed-tools`; trigger analysis, `description_digest`, and the declared-vs-observed tool assertions all use the second (broader) value. An author gets a skill approved on the benign first occurrence while the effective trigger string and declared scope are the hidden second.
- **Fix:** parse with a loader that detects duplicate keys and appends a reported problem listing the shadowed keys.

## BW-21 — Hostile frontmatter crashes `load_skill` with an uncaught `RecursionError` (LIVE)
- **Where:** `src/bellwether/skill/frontmatter.py:128-135` (`yaml.safe_load` guarded only by `except yaml.YAMLError`).
- **Status:** CONFIRMED by repro. `RecursionError` is not a `yaml.YAMLError` subclass, so a ~1.2 KB `SKILL.md` with a ~600-deep nested flow value (`[[[…]]]`) escapes the guard and raises out of `load_skill`.
- **Impact:** the module contract is explicit — *"an unparseable frontmatter is a finding about the skill, not a failure of the tool"* — but this aborts ingestion before any sandbox exists; a skill reliably forces its own evaluation to error, and depending on caller handling can abort an enclosing batch run. A DoS / evaluation-evasion lever.
- **Fix:** broaden the guard to also catch `RecursionError` (and `ValueError`) around `safe_load`, converting to a reported problem; optionally bound nesting depth pre-parse.
- **Repro:** `scratchpad/verify_frontmatter.py`.

## BW-22 — Unbounded `read_bytes()` on every package file OOMs the loader (LIVE)
- **Where:** `src/bellwether/skill/digests.py:108` (`data = absolute.read_bytes()`); also `package.py:282` (`read_text()`).
- **Status:** CONFIRMED by inspection — no chunking, no size cap.
- **Impact:** the same DoS the overlay collector was explicitly hardened against (spec-notes §10.0 switched *that* path to fixed-size chunk hashing). A skill package that commits a multi-GB file OOMs `load_skill` during digest computation, before any sandbox exists — another route to force `not_evaluable`/kill the gate.
- **Fix:** hash files in fixed-size chunks (mirror the collector); optionally cap/stream-skip oversized files and report them.

## BW-23 — base64 adjacent to alphabet noise defeats canary decoding (LATENT)
- **Where:** `src/bellwether/capture/canary.py:204` — `decoded_forms` decodes only the maximal `_BASE_TOKEN_RE` run at its own alignment.
- **Status:** CONFIRMED (agent repro): `base64(marker)` with a non-multiple-of-4 prefix (`"A"`, `"AB"`, `"v2"`) is missed; `evil.com/exfil/<b64>` merges `exfil/`+payload into one 6-bit-misaligned token and is scrambled. JSON framing is safe only because quotes terminate the run.
- **Impact:** once egress-body/output/tool-arg scanning is wired, `evil.com/d/<base64-secret>` is not decoded. Latent until those callers land.
- **Fix:** attempt decoding at each of the 4/8/2 sub-alignments of a long run (or decode sliding sub-runs); document as a distinct gap from the chunking xfail.

## BW-24 — One `preceded_by_read` flag per body downgrades a co-located non-read canary (LATENT)
- **Where:** `src/bellwether/capture/canary.py:284,307` — a scalar `preceded_by_read` is stamped on every canary in the body.
- **Status:** CONFIRMED (agent repro): a model-endpoint body with a legitimately-read `c1` and a never-read `c2`, scanned with `preceded_by_read=True`, classifies **both** as `info`; `c2` should be `high` (§10.4.1: "no preceding read → obtained by some other path").
- **Impact:** a skill reads its declared canary and, in the same request, smuggles a second canary obtained elsewhere; the second is reported `info` instead of `high`. Latent until model-endpoint body scanning is wired.
- **Fix:** thread read-state per canary (a `set[str]` of read canary ids) and classify each finding against whether *that* id was read.

## BW-25 — Canary finding `offset`/`via` is non-deterministic across `PYTHONHASHSEED` (LATENT)
- **Where:** `src/bellwether/capture/canary.py:300-306` (best-selection over `set` iteration) + `_rank` at `:322-325` (which omits `offset`, so equal-length equal-class hits at different offsets tie and resolve by hash order).
- **Status:** CONFIRMED by repro: for `marker[0:20] + marker[10:30] + reverse(marker[10:30])`, seed 7 → `offset=0`, seeds 0/1/2/3 → `offset=20`. Presence/absence is stable; only the metadata that lands in the redaction fingerprint is not.
- **Impact:** violates §24 (output must not depend on `hash()`); a `<canary:c1@offset=…>` fingerprint would differ byte-for-byte across machines, and a §24 byte-compare test would fail off the pinned seed. `test_findings_are_sorted_deterministically` only checks `canary_id` sort order and never varies the seed. Latent because the only wired caller (DNS) yields `offset=-1`, and `redact_canaries` has no production caller yet.
- **Fix:** make the selection total and order-independent — fold `offset` (and a `via` order) into the comparison key, or sort `haystacks` before the inner loop.
- **Repro:** `scratchpad/verify_canary_det2.py`.

## BW-26 — Epoch anchoring assumes monotonic spine timestamps (LATENT)
- **Where:** `src/bellwether/trace/epochs.py:103-104,178-198` — `window_starts` is built in seq order, then `_epoch_for` uses `bisect.bisect_right`, which requires a sorted list.
- **Status:** CONFIRMED (agent repro). If two spine tool-call timestamps are non-monotonic in seq order (clock skew / NTP step on a live harness, or near-simultaneous parallel calls stamped out of order), the bisect silently picks the wrong window and places a timing-anchored event in the wrong epoch.
- **Impact:** two behaviourally-identical runs get different `step_sequence` → spurious trajectory variance feeding the noise floor (WP-7/WP-19, the pair CONTRIBUTING flags as load-bearing). Not triggered by the monotonic `ScriptedClient`, but the next brick is a live harness; the done-when test jitters only *non-spine* events, so the spine-monotonicity assumption is untested.
- **Fix:** clamp each `window_start` to be ≥ the previous (or assign epochs by a direct spine-order scan instead of `bisect`); add a test that jitters spine timestamps into non-monotonic order.

## BW-27 — `_norm_host` misparses a `userinfo@` authority (LATENT)
- **Where:** `src/bellwether/capture/egress.py:69-74` (`_norm_host` strips a port with `rsplit(":",1)` and never handles RFC-3986 userinfo).
- **Status:** CONFIRMED by repro. `_norm_host("api.anthropic.com:443@evil.com")` → `"api.anthropic.com"`, so it classifies `model_api` and is allowlist-permitted, while a real client (`urlsplit`) resolves the host to `evil.com`. The benign direction breaks too: `user:pass@api.anthropic.com` normalises to `"user"` and is blocked.
- **Impact:** in the pure decision core (which spec-notes designates the trustworthy boundary the "thin glue" sidecar hands raw fields to), an `evil.com` authority reads as the provider. **Reachability is low:** mitmproxy's `pretty_host` is the already-resolved destination host, so a raw authority with userinfo is unlikely to reach `_norm_host` end-to-end — hence Low/Medium, not High. But the sibling `provider_hosts` already parses with `urlsplit`, so the correct tool is in the same file.
- **Fix:** parse with `urlsplit(f"//{host}")` (or split off `userinfo@` and validate a numeric port) so `permits`/`classify` see the host a real client routes to.
- **Repro:** `scratchpad/verify_net.py`.

---

# Low

- **BW-28 — `language_lint` misses `guarantee`/`prove`/`ensure`/`vouch` (LIVE).** `tools/language_lint.py:46-52` bans `safe/secure/verified/approved/certified`, but CLAUDE.md states the lint bans `safe/secure/guarantee/prove/ensure/verified/vouch`. Confirmed: strings "this result proves…", "guarantees no exfiltration", "ensures…", "will vouch for…" all pass the lint. The four missing words include the strongest proof-implying ones. Fix: add them to `BANNED_WORDS` (with `bw-lang-ok` markers for legitimate uses), or correct the doc. Repro: `scratchpad/lang_probe.py`.
- **BW-29 — `pin_lint` coverage gaps (LIVE).** `tools/pin_lint.py` catches `uses:`, `*IMAGE` env vars, `docker pull`, and Dockerfile `FROM`, but **not** `docker run <img>`, GitHub Actions `container: image:tag`, or `services: … image:`. None are used today, so it's latent — but a supply-chain linter should cover the forms it doesn't. Fix: add those patterns.
- **BW-30 — `GIT_SSL_CAINFO` missing from the CA table (LIVE).** `src/bellwether/capture/ca.py:54-60` ships `system store` + `NODE_EXTRA_CA_CERTS`/`REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`/`CURL_CA_BUNDLE`, but spec §9.2 (line 942) also lists `GIT_SSL_CAINFO` (git over HTTPS — the "dynamic payload fetch" vector). `test_ca.py:21` uses a subset (`<=`) assertion, so it stays green with the row missing. Fix: add the mechanism; change the test to assert the exact required set.
- **BW-31 — Credential exposed by default dataclass `repr` (LATENT).** `ProxyDecision.upstream_headers` (`proxy_core.py:38-52`) holds the real key post-injection with no `repr=False` (unlike `ProxyAddon._flows`), and `AnthropicClient` (`live_client.py:205`) is a plain dataclass whose `repr` shows `api_key`. Not logged today, but a future `logger.debug("%r", …)` or exception context would spill the key into CI logs/artifacts. Fix: `field(repr=False)` on both.
- **BW-32 — `_AUTH_HEADERS` provider-incomplete (LATENT).** `credential.py:45` injects only `authorization`/`x-api-key`/`api-key`/`anthropic-api-key`; a provider using `x-goog-api-key` (Gemini) never gets the real key injected → request fails with the scoped token. No leak. Fix: make the injectable-header set provider-driven.
- **BW-33 — `interception_confirmed` asymmetric normalisation (LIVE).** `ca.py:97` normalises the recorded hosts but compares `probe_host` raw, so `interception_confirmed(["example.test"], "Example.Test")` → `False`. Fail-closed (doctor fails loud on a working run — safe direction), but the test only exercises the recorded side. Fix: normalise `probe_host` too.
- **BW-34 — `changed-skills` path escape (LIVE, not reachable via `git diff`).** `cli/changed.py:25` (`skill_dir_for`) attributes a `../outside/evil.py` to a `SKILL.md` outside the repo root (`root / PurePosixPath("/etc") == /etc`). `git diff --name-only` never emits such paths, but `changed-skills` also reads arbitrary stdin. Fix: reject/skip paths that resolve outside `root` before the `is_file` probe.
- **BW-35 — `violations()` doesn't report weakened seccomp/resources (LATENT).** `isolation.py:80-102` covers cap-drop/read-only/no-new-privileges/socket/root-uid but not a non-default `seccomp` (a run under `seccomp=unconfined` renders the weakened flag yet reports fully hardened) nor unbounded memory/cpus/pids. Only reachable via a code change or alternate backend today. Fix: flag `seccomp != "default"` in `violations()`.
- **BW-36 — Host disk/collector-memory DoS (LIVE).** `sandbox/docker.py:319` (`--tmpfs {target}` with no `size=`) and `overlay.py:159` (`sorted(upper.rglob("*"))` materialised in host memory, post-exit, unbounded) let a skill fill host disk or OOM the collector — the "observed process decides whether the observer finishes" shape (cf. the fixed FIFO hang) via resource pressure. Fix: cap tmpfs size; bound the overlay walk (degrade the plane to `partial` with a reason rather than an unbounded `rglob`).
- **BW-37 — Scenario `env` has no delivery path (LIVE).** `cli/execution.py:180-182` uses `plan.scenario.prompt` but never `plan.scenario.env`; the executor's only `extra_env` source is the proxy. §7.2's per-scenario `env` (whose "values may be canaries", e.g. `INTERNAL_API_TOKEN`) can't reach the container, so an env-var exfiltration channel is untestable and reads clean. Fix: thread `plan.scenario.env` (canary-substituted) into `build_argv`.
- **BW-38 — `constants.EXIT_REASONS` dead + wrong (LIVE).** `constants.py:94-102` maps `sandbox_error → not_evaluable` (should be `fail`), omits `harness_error`, and carries a bogus `completed` value — contradicting the authoritative `assertions/results.py:52-55` despite a comment claiming the two "cannot drift." Unused today; a future consumer of the "canonical" map would silently mis-gate `sandbox_error` and `KeyError` on `harness_error`. Fix: delete it, or make it the single source `results.py` derives from.
- **BW-39 — Windowed canary scan is ~4 s/MB, no size bound (LATENT).** `canary.py:270-275` builds ~435 windows × #canaries × #decoded-forms, each a full-form substring search; a clean 1 MB body takes ~3.6 s (`decoded_forms` alone is 91 ms). §10.4 scans all output/files/egress bodies, so a skill emitting a multi-MB file imposes seconds of host CPU per repetition. Fix: cap scanned length (align with the §10.5 body-truncation cap); short-circuit when a full-marker `in form` already hit.
- **BW-40 — `_norm_host` accepts odd spellings (LIVE).** `egress.py:69-88` treats `.api.anthropic.com` (leading dot) as a subdomain match, strips brackets off non-IPv6 `[host]`, and strips a non-numeric segment after `:` as a "port"; mirrored in `dns.py:41-57`. Fail-closed for the default provider set (odd spellings don't route), but a security-boundary parser shouldn't be this permissive. Fix: reject a leading-dot/empty first label, only strip brackets for a valid IPv6 literal, validate numeric ports — ideally share one parser with `provider_hosts`.
- **BW-41 — `compute_bci` silently drops an unweighted component (LATENT).** `metrics/bci.py:94-101` iterates `weights.items()`, so a component present in `components` but absent from `weights` vanishes from both `components_used` and `components_excluded` — defeating the §13.7 audit guarantee if custom weights ever omit a key. Latent (the orchestrator always passes the full default weights). Fix: iterate the union, or assert `set(components) ⊆ set(weights)`.
- **BW-42 — Trajectory single-linkage chaining hides variance (LATENT, spec-sanctioned).** `metrics/trajectory.py:100-187` connected-components at threshold 0.2 can collapse a fan of 9 sequences whose endpoints are 44% apart into one cluster (`modal_cluster_share=1.0`), lifting BCI enough to clear `min_bci`. Inherent to the mandated single-linkage; the intended mitigation is the §24 noise-floor calibration (not built) and the (unenforced, BW-10) `max_mean_edit_distance` gate. Fix: prioritise wiring BW-10 and the noise floor.
- **BW-43 — Triple-nested encoding not decoded (LATENT).** `canary.py:197` (`nest=1` → 2 decode rounds) catches 1×/2× base64 but not 3×/4×. Matches the "one round of nesting" docstring; noted for the record. Fix: none required unless raising the depth.
- **BW-44 — Billion-laughs alias DAG (LATENT).** `skill/frontmatter.py:129` (`safe_load` permits unbounded aliases) + `:86-88` (unknown fields preserved). A 460-byte frontmatter with 9 alias levels parses instantly but `canonical_json(unknown_fields)` OOMs (~33 s to 1 GiB). Latent: nothing serialises `unknown_fields` yet, but the landmine is armed at ingestion. Fix: cap/forbid YAML aliases at ingest and report their presence.

---

# Info / verified-clean (do not "fix")

An honest review names what's solid, so a downstream agent doesn't churn on non-issues.

- **BW-45 (Info) — machinery exclusion is case-sensitive.** `payload.py:63,83` uses `startswith("evals/")`; on a case-insensitive FS `EVALS/manifest.yaml` isn't *labelled* machinery — but it **fails closed** (the restrictive allowlist doesn't match it, so it isn't copied). The allowlist is the real guarantee and it holds; only the labelling is brittle.
- **Credential isolation (the crown jewel) holds.** The real model key is never placed in the container env, an argv, a config file, a flow record, or a trace artifact; injection fires only for a `model_api`-classified request whose host is an exact provider key; the recorded flow is built from pre-injection headers with auth headers redacted; the sidecar passes keys by name only (`-e KEY`, value in docker's own env); `for_sidecar` reconstruction fidelity is correct; blocked requests never inject and never consume the cap. Verified across many adversarial paths.
- **Network isolation is genuinely strong.** `create_network(internal=True)` builds a gateway-less bridge; the sandbox is only ever given that bridge or `none` and is never `connect_network`'d; the sole `connect_network` targets the proxy sidecar. No Docker socket, no `--privileged`, empty `cap_add`. Invariant 3 is asserted by reading `/proc/net/route` inside a real container.
- **The overlay collector can't be hung or escaped.** FIFOs/sockets/devices are recorded by presence and never opened (the fixed hang), symlinks are recorded via `readlink` and never followed (verified `rglob` doesn't descend a symlinked dir), regular files are chunk-hashed, whiteout/opaque-dir handling is kernel-robust and deterministic.
- **Path injection is closed.** `slugify_name` neutralises `name: /etc`, `..`, `:`-injection into `-v`; the derived install path is asserted within the install root.
- **The payload allowlist is a true allowlist.** `evals/` is guarded first in both `matches()` and `split()`, staging adds post-hoc `contains_machinery()`/`EVALS_DIR` leak assertions, and staging symlink containment correctly refuses absolute/`..`/chained links that resolve outside root. (The digest's blind spot is BW-01, upstream of this.)
- **The statistics core is correct.** Wilson intervals match an independent implementation to 1e-6 and reproduce the §13.1 table exactly; `POCOCK_BOUNDARY_Z` are the standard published constants; `outcome_consistency` is symmetric and rounding-independent; BCI is bounded/monotone with a zero-weight guard; `run_outcome` implements the §12.7 mapping exactly (including `excluded_quality` for `possible_egress_induced_failure`); precondition and weight-validation checks are fail-closed.
- **The verdict engine composes correctly.** Worst-per-target wins; a required `not_evaluable` → `block` → `not_ready` even under `descriptive_only`; `descriptive_only` is capped at `conditional`; the overall verdict can never be more favourable than the worst gate; egress-not-observed correctly resolves to `not_evaluable` and (under the block disposition) blocks — a skill cannot reach `ready` on the egress gate without an observed-clean run.
- **The HTML report has no XSS.** Every skill-controlled string (`skill.name`, gate fields, capability names, output-derived text) is passed through `_esc()` = `html.escape(..., quote=True)`, including inside `title="…"` attributes.
- **The live client, PR-comment, and api-loop tool paths are clean.** Unknown `stop_reason` → `other` (never a silent `end_turn`); a silent model swap is visible via `model_id_reported`; `_require_trusted_anthropic_endpoint` pins the base URL; the GitHub token travels only in the `Authorization` header (never a URL/body/log); api-loop tools exec in-container with `cat -- path` / positional `$1` (no host-side path resolution, no argv injection), and `fetch` is refused.
- **No hard-coded model identifiers.** A full-tree sweep found zero literal model ids in `src/`; templates use `frontier`/`mid`/`small` aliases and `<fill in…>` placeholders; `claude-code`/`anthropic` are harness/provider names.
- **Determinism holds.** The offline suite is byte-stable under `PYTHONHASHSEED=12345`; `bellwether demo` regenerates its committed reports with no diff. (The two determinism *edges* found — BW-25, BW-26 — are both latent.)
- **The CI workflow makes the right trust choice.** It uses `pull_request` (not `pull_request_target`), so fork PRs never see secrets; the paid run is gated on both the `bellwether-run` label and the `ANTHROPIC_API_KEY` secret; the key is preserved into the sudo'd run and never reaches the sandbox.

---

## Cross-cutting themes (for triage)

1. **"Declared but not wired" is the dominant class** (BW-02, BW-08, BW-09, BW-10, BW-12, BW-18, BW-19, BW-37). Controls exist, are unit-tested in isolation, and are never connected to `bellwether run`. This is the highest-leverage area: a config knob or gate that silently does nothing is worse than an absent one, because the verdict looks earned.
2. **Two gates are actively wrong, not just missing** (BW-03 inverted, BW-04 bypassable) — these fail *open* for a security gate and need fixing before the tool is leaned on.
3. **Untrusted-input robustness at ingestion** (BW-01 collision, BW-21 crash, BW-20 shadowing, BW-22 OOM, BW-44 alias DAG) — the skill package is attacker-authored in external mode, and the parse/digest path is less hardened than the runtime capture path (which *has* been hardened against exactly these shapes).
4. **The differentiating metric (WP-7) has two real corruptions** (BW-05 live, BW-26 latent) — CONTRIBUTING singles this out as the thing that "silently corrupts everything built on top," and the noise-floor calibration (WP-19) that would catch it isn't built yet.
5. **Tests that assert the wrong thing recur** — the project's own stated failure mode. Concrete instances to distrust: `test_a_symlink_is_hashed_not_followed` (BW-01), `test_a_rare_high_risk_capability_blocks_at_every_look` (BW-03, asserts membership not gating), `test_a_degraded_write_plane_blocks_write_assertions` (BW-06, only `unavailable`), `test_findings_are_sorted_deterministically` (BW-25, never varies the seed), `test_the_mechanism_table_covers_the_runtimes…` (BW-30, subset assertion), `test_sandbox_host_side.py:508` (BW-18, asserts the profile value not the container).

## Appendix — reproduction

All reproductions are throwaway scripts under `/tmp/claude-0/.../scratchpad/` (prefixes: `verify_*`, `cred_*`, `net_*`, `canary_*`, `sbx_*`, `skill_*`, `trace_*`, `metric_*`, `cfg_*`), each runnable with `uv run python <script>` from the repo root. No tracked source or test file was modified during this review. The six checks and the full offline + docker suites were green before and after.
