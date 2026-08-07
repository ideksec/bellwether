# Status — where the build is, and what to pick up next

The entry point for a new session. Read this, then `docs/BUILDPLAN.md` for the next work
package, then `docs/spec.md` for the detail of whatever you are building.

Last updated at the end of the WP-16 (canaries) + WP-14 (CA trust-chain core) work. **Update
it at the end of a session, not the start** — a status file that lags is worse than none,
because it is trusted.

---

## Where the build is

| Work package | State |
|---|---|
| WP-1 — scaffolding, config, ground rules | **done** |
| WP-2 — skill parsing, three digests | **done** |
| WP-3 — ARF schema, writer, reader | **done** |
| WP-4 — sandbox lifecycle, host and container halves | **done** |
| WP-5 — capture: Plane A and Plane B | **done** |
| WP-6 — `api-loop` harness adapter | **done** |
| WP-7 — canonicalization and epoch anchoring | **done** |
| WP-8 — platform baseline | **done** |
| WP-9 — assertions, outcome composition, golden traces | **done** |
| WP-10 — metrics | **done** |
| WP-11 — verdict engine and precondition check | **done** |
| WP-12 — reporting (`summary.json` + Markdown) | **done** |
| Analysis orchestrator (trace → verdict → artifact tree) | **done** |
| Sandbox execution driver (`RunExecutor`) | **done** |
| ▶ First-light checkpoint — `benign-stable` end to end in a real sandbox | **reached** |
| WP-13 — recording proxy: egress, credentials, decision core, addon, sidecar entry+image+launcher, internal-bridge isolation, **live interception** | **done** — the full done-when (inject-on-forward, block-on-deny, no credential in the artifact) runs in a real container topology on CI |
| WP-14 — CA trust chain (mechanism table, install env/commands, confirm predicate) | **host core done** — the live doctor probe is CI-only |
| WP-16 — canaries: mint, decode-then-match, classify, redact | **done** |
| Live model client (`harness/live_client`) — Anthropic Messages API behind the `ModelClient` seam | **done** — `openai_compatible` is a follow-on |
| WP-15, WP-17 – WP-20 — Phase B | not started |

608 tests: 566 offline, 42 under the `docker` mark. All green.

`bellwether run` is not usable **from the CLI** yet: the whole pipeline runs end to end in
tests (first-light is reached), but a CLI run of an arbitrary skill needs the WP-13 live
model client, so `run` exits 3 and names that package rather than printing an empty result
that would read as a clean run.

### What WP-12 built

The report layer, in `bellwether.report` (renders; never computes — everything here was
decided upstream in `metrics` and `verdict`):

- **`summary.py`**: the schema-versioned `summary.json` (§17.2) as `extra='forbid'`
  pydantic models, `render_summary_json` routing through `determinism.canonical_json`
  (sorted keys, floats rounded once), and `summary_json_schema()` — the JSON Schema is
  *generated* from the models and shipped at `report/schemas/summary.schema.json`, with a
  drift test asserting it matches. The done-when (byte-identical across two invocations)
  falls out of the determinism layer.
- **`figures.py`**: the three §13.8 figures as deterministic monospace text — the
  per-scenario strip chart (five distinct glyphs; a timeout is not drawn like an
  assertion failure; look boundaries marked; `n` and the look on every row), the
  trajectory cluster list (largest first), and the **capability heatmap** (tier-3 grouped
  under tier-1, high-risk flagged — the flagship). Row order is sorted, so shuffling the
  input never changes the bytes.
- **`markdown.py`**: the PR comment (§18.2), hand-rolled so the presentation rules with
  teeth are unit-tested Python, not template branches — the BCI never rendered without
  the pass rate beside it, the "consistently failing" annotation wherever `p̂ < 0.5`, and
  the §2 limitations footer rendered whole from `constants.REPORT_LIMITATIONS`.

WP-12 is `summary.json` + Markdown; the eleven-view HTML site (§17.4), the two findings
containers (§17.3), and the artifact tree (§17.1) are a later package (see spec-notes
§17.4). 16 report tests.

### What the analysis orchestrator built

The analysis half of `bellwether run`, in `bellwether.cli.orchestrator` and
`bellwether.cli.artifacts` — the thing that *assembles* every stage below it into a
verdict, but does not execute runs itself:

- **`analyse_run`**: one trace → its per-run reading (the §12.7 run outcome from the
  assertion results, the §11.4 canonical capability sets, the trajectory step sequence).
- **`aggregate`**: a repetition set → one `SetReading` through the §13 metrics — sequential
  pass-rate design (§13.1), risk-weighted capability Jaccard (§13.5), trajectory clustering
  (§13.4), the BCI (§13.7).
- **`orchestrate`**: populates the §16.2 gates from the readings (worst target per gate),
  composes the verdict, assembles the `Summary`, and writes the §17.1 artifact tree
  (`summary.json`, `verdict.json`, `report/pr_comment.md`, per-run `traces/` and
  `canonical/`).
- **`RunExecutor`** is the seam for the execution half.

### What the execution driver built (first-light reached)

`SandboxRunExecutor` in `bellwether.cli.execution` — the WP-6 container wiring lifted behind
the `RunExecutor` seam. Given a `RunPlan` it prepares a fresh sandbox, runs one repetition
through the `api-loop` adapter, captures both planes on the host, assembles the ARF trace,
and returns an `ExecutedRun`. One repetition, one fresh sandbox (a repetition set is a
distribution over *independent* runs — sharing state would fabricate consistency). The model
side is injected as a `ModelClient` per target, so the `harness → sandbox` boundary and the
no-hard-coded-model rule both hold; at first-light the client is scripted (the live client
lands in WP-13).

**The first-light checkpoint is reached** (`test_execution_docker.py`): `benign-stable` runs
end to end in a *real* container six times — overlay mount, container exec, two-plane
capture, proxy and resolver bypassed — the orchestrator turns those six real traces into a
**`conditional`** verdict (every evaluable gate passes; egress `not_evaluable` with a reason
until the proxy lands), and the artifact tree lands on disk. The skeleton walks. The
`conditional`-not-`ready` result is the tool refusing to call an unobserved channel clean,
holding even for its own first run.

### What WP-13 increment 1 built

The **host-side egress semantics** — the deterministic core of Plane D, in
`bellwether.capture.egress` and `trace.egress_actions`, offline and fully tested (25 tests):

- **`classify_egress`** (§10.5.0): `model_api` / `harness_infrastructure` /
  `skill_attributed`, model API checked first, label-boundary suffix matching so a lookalike
  domain cannot pose as the provider. Only `skill_attributed` counts toward `no_egress` —
  without this, telemetry from any real agent CLI makes `no_egress` never pass.
- **`EgressAllowlist`** (default-deny): providers + declared infrastructure + explicit extras
  permitted; everything else blocked, with a reason. A blocked attempt is evidence, not an
  error.
- **`CapLedger`** (§10.5.1): per-run request and byte caps on the sandbox-scoped token, the
  bound on residual-channel exfiltration; a crossed cap is `budget_exceeded`.
- **`redact_headers`**: an allowlist (keep these), not a denylist, so a *new* auth header
  can't leak a credential into an artifact. **`make_flow`** reduces the request body to a
  digest + length — no body value ever reaches a record.
- **`correlate_egress_induced_failure`** (§10.5.0): a run with both assertion failures and
  blocked egress is flagged, to be excluded from quality metrics and kept for security.
- **`RecordingProxy`** is the seam for the sidecar; its base raises rather than silently
  observing nothing (a zero-egress trace reads as a clean skill).

### What WP-13 increment 2a built

The **credential-isolation core** (§3.3 invariant 1 — the most important security property
of the tool), in `bellwether.capture.credential`, offline and fully tested (14 tests):

- **`mint_sandbox_token`**: a per-run, reproducible, opaque sandbox-scoped token — worthless
  outside the proxy; its only power is that the proxy recognises it and swaps in the real key.
- **`strip_and_inject`** (§10.5.1): the proxy-side transform that replaces the scoped token
  with the real key in an auth header, preserving the scheme, and injects *only* for the
  token it minted (a skill's own key is never swapped for Bellwether's).
- **`CredentialBroker`**: the host-side ledger. `sandbox_env(provider)` is what the container
  receives — the scoped token under the provider's own key var, **never the real key**;
  `inject` performs the swap; `leaks_a_real_key(text)` is the guard teardown and the done-when
  use to assert no artifact holds a credential. The real key is read from the host
  environment and leaves only through `inject`.
- **`proxy_environment`**: the routing env (HTTPS_PROXY etc., no bypass), plus the CA-bundle
  vars for WP-14.

The end-to-end invariant is tested by joining this to increment 1: an injected request really
carries the real key on the wire, but the flow record redacts the auth header, so the key
reaches the provider and nothing else.

### What WP-13 increment 2b-i built

The **proxy decision core** — `decide_request` in `bellwether.capture.proxy_core`, the pure
per-request logic the mitmproxy addon will run, offline and fully tested (10 tests). The
*order* is the security property, so it is fixed here rather than left to the addon:
allowlist-check (block a denied host, record it) → cap-check (refuse before forwarding, so
the residual-channel bound actually holds; `budget_exceeded`) → inject the real key for a
permitted `model_api` request → record the flow either way. Tested edges include: a blocked
request never consumes the cap (a skill can't exhaust the budget with denied attempts) and
the recorded flow never holds the real key *or* the scoped token even after injection. This
is the whole "what the sidecar decides" — the container that runs it is all that's left of
WP-13.

### What the live model client built (§9.5, §9.3)

`bellwether.harness.live_client` — the real HTTP client behind the `ModelClient` seam, the last
piece of logic before `bellwether run` can drive a real skill (10 tests):

- **`AnthropicClient`** implements `complete(ModelRequest) -> ModelTurn` against the Messages API.
  The `api-loop` loop runs host-side (its tools exec into the sandbox), so this client runs with the
  real key directly — the proxy observes the *sandbox's* egress, not the harness's own model calls;
  the in-container `claude-code` agent (WP-17) is the one whose calls route through the proxy.
- The wire work is **pure and seamed**: `anthropic_request_body` and `parse_anthropic_response` are
  functions, and the HTTP call is a `transport` seam, so the request shape, response parsing, auth
  headers (`x-api-key`, `anthropic-version`), and error mapping are all tested without a network or a
  key. Two edges with teeth: an unknown `stop_reason` maps to `other`, never silently to `end_turn`;
  and `model_id_reported` is recorded as what the provider *said it served*, so a silent model swap
  is visible (§9.3). `build_model_client` dispatches on provider type — `openai_compatible` raises a
  clear "not yet" because its Chat Completions shape needs a message translation the loop's
  Anthropic-shaped messages don't carry.

### What the live interception test proved (§10.5, §3.3 — the WP-13 done-when)

`tests/test_sidecar_docker.py` now stands the whole plane up in a real container topology on CI and
asserts the done-when end to end: a **client** container sends the *scoped* token through the proxy;
a permitted model-API call (a **peer** container named as the provider endpoint, so docker's embedded
DNS resolves it and classification is plain string matching) is forwarded with the **real key
injected on the wire** — the peer echoes it back — while the scoped token does not survive the swap;
a denied host (`evil.example.com`) is **blocked with a 403** the client sees, short-circuited before
any forward or DNS; and the flow log records both flows while holding **neither the real key nor the
scoped token**. All three containers sit on a user-defined `--internal` bridge, so §3.3 invariant 3
holds at the same time. On any failure the sidecar, peer, and client outputs are dumped into the
assertion, so a remote failure is diagnosable from the job output. The credential-isolation invariant
(§3.3 #1 — the most important property in the tool) is now proven live, not just in unit tests.

### What the sidecar image built (§10.5)

The **container that runs the addon**, in `sidecar/proxy` — proven on CI:

- **`sidecar/proxy/Dockerfile`** builds from a **digest-pinned** `python:3.12-slim`, installs
  `mitmproxy==12.2.3` (exact — its addon API is not stable across majors), installs Bellwether from
  `pyproject.toml` + `src` (validated: the wheel builds with a static version, so no git in the
  image), and copies the `mitmdump` loader `sidecar/proxy/proxy_entry.py` to the fixed
  `SIDECAR_ENTRY_PATH`. There is deliberately no `ENTRYPOINT` — the launcher passes the full
  `mitmdump … -s …` argv so the exact command stays recordable, as the sandbox backend does.
- **`tools/pin_lint.py` now also lints Dockerfiles** — every `FROM` that names a registry image must
  carry an `@sha256:` digest (build-stage `FROM`s and `scratch` exempt). A floating base is the same
  mutable-input hole as a floating action, one layer down.
- **`tests/test_sidecar_docker.py`** (CI-gated on `CI`, since the build needs open egress) builds the
  image and starts the sidecar through the real `MitmproxySidecar`, asserting the empty flow log
  appears — proof `mitmdump` came up and registered our addon, i.e. Bellwether imports in the
  mitmproxy runtime and the inside-the-container half runs for real. Container logs are dumped into
  the assertion on a readiness failure so a first-run CI failure is diagnosable from the job output.

The **full interception path** — a client container routed through the proxy, a permitted call
recorded with the real key injected and a denied one blocked, plus CA trust — is the follow-up that
closes the WP-13 done-when, standing on this now-proven image.

### What the sidecar host launcher built (§10.5)

The **lifecycle around the `mitmdump` container**, in `bellwether.capture.sidecar`, offline and
fully tested via a `runner`/`sleep` seam (9 tests):

- **`MitmproxySidecar(RecordingProxy)`** — the proxy the analysis path talks to. `start` writes the
  non-secret config to the shared volume, launches the sidecar on the run's internal bridge, and
  waits for ready; `flows` reads the flow log back; `stop` force-removes the container. It exposes
  `proxy_url` — the sidecar reachable by container name on the bridge — for the sandbox's
  `HTTPS_PROXY`.
- **The real key never reaches the command line.** The sidecar needs the real credential, but a
  `-e KEY=value` flag would put it in the process table and any recorded command. The launcher
  passes `-e KEY` (name only) and runs `docker` with the key in its *own* environment, so docker
  forwards the value and it appears in no argv, no config, no artifact (§3.3). The load-bearing
  test asserts the key's *value* is in no argv token.
- **Readiness is the flow log appearing, not a guess.** The entry writes an empty flow log the
  instant it loads, so the log's appearance proves mitmdump came up and registered the addon; a
  timeout with no log is a loud failure, never a clean-looking zero-egress run. A stale log from a
  crashed prior run is cleared before start, so readiness can't be trivially true and this run
  can't inherit another's flows.

### What the sidecar entry built (§10.5)

The **inside-the-sidecar half** — how the proxy container rebuilds the run's `ProxyAddon` from a
config file and its environment, in `bellwether.capture.sidecar_entry` and three new
`CredentialBroker` methods, offline and fully tested (11 + credential tests):

- **The broker's sidecar halves**: `sidecar_export` hands over the *non-secret* mapping (per
  provider, its `api_key_env` name and scoped token — the token is already what the container
  holds, so exporting it leaks nothing); `sidecar_real_key_env` is the one place a real key leaves
  the host, and it goes only into the sidecar's own environment; `for_sidecar` rebuilds the broker
  from those two parts, skipping any provider whose key is absent from env exactly as `for_run`
  does on the host. The load-bearing test is **reconstruction fidelity**: the rebuilt broker
  injects the real key for the *same* scoped token the host minted — if that mapping did not
  survive the round trip, every model call would go out bearing a worthless token and injection
  would silently fail.
- **`SidecarConfig`** (canonical-JSON serialisable, no secrets) + **`build_addon`** rebuild the
  `ProxyAddon` from the same endpoints, allowlist and caps the host's `decide_request` used.
  **`block_response_args`** reduces a `BlockResponse` to the pure `(status, body, headers)` triple
  mitmproxy's `http.Response.make` takes, so the block path is tested without mitmproxy — the one
  genuinely mitmproxy-shaped line (assigning `flow.response`) is validated by the CI docker test.
  **`load_addon_from_env`** is the mitmdump entry: it refuses to run without its config (an
  unconfigured proxy would forward everything and record nothing) and writes an empty flow log at
  construction, so "the proxy ran" is true from t=0 and a *missing* log unambiguously means it
  never started.

### What the proxy addon built (§10.5)

The **mitmproxy-shaped glue over the decision core**, in `bellwether.capture.proxy_addon`,
offline and fully tested (13 tests):

- **`ProxyAddon`** is the per-request brain the sidecar runs: translate a mitmproxy request →
  `decide_request` → apply. It owns the run's mutable egress state (the `CapLedger`, the
  accumulated flows), and either *mutates the outgoing request's headers in place* — so a
  permitted model-API call really carries the real key on the wire — or returns a `BlockResponse`
  the entry script renders as a synthetic 403 (allowlist denial) or 429 (`budget_exceeded`). It
  adds no security logic; the order and decisions are all in `decide_request`. `RequestLike` is
  the exact structural subset of `mitmproxy.http.Request` it touches, so it is tested with a plain
  fake — no mitmproxy, no container — and the entry script in the image stays too thin to hide a
  bug.
- **The flow-record contract** (`flow_record_line` / `read_flow_records`): the sidecar appends one
  canonical JSON line per flow to a shared-volume file, the host reads them back into `EgressFlow`
  objects for `trace.egress_actions`. A *missing* log raises rather than returning `[]` — the
  sidecar always writes it, so its absence means the proxy never ran, and a zero-egress trace that
  reads as a clean skill is the exact failure this plane exists to prevent; a *written-but-empty*
  log is a legitimate observed-zero-egress run. The tested edge that matters: a blocked flow's
  `None` response fields survive the round trip as `None`, not `0`.

### What the internal-bridge isolation built (§3.3 invariant 3)

The **routing half of "no unmediated route out"**, in `bellwether.sandbox.docker` —
`create_network`/`remove_network` and a `network` argument already threaded through `run`
and `build_argv` (4 docker tests, `test_network_docker.py`):

- **`create_network(name, internal=True)`** builds a Docker `--internal` bridge: a container
  on it reaches only its peers, so the sole routes out are the recording proxy and resolver,
  which are those peers. A socket to a public address is refused by the kernel with "network
  is unreachable" *before* any userspace egress code runs — the isolation is a routing fact,
  not a policy the container could talk past. Creation is deliberately non-idempotent: a name
  collision means a leaked network whose peers we did not place, so the caller removes and
  retries rather than silently reusing it.
- The docker test proves invariant 3 by reading `/proc/net/route` inside a real container on
  the bridge — a subnet route exists (attached to a real bridge) but **no default route**
  (no way out) — and contrasts it against `--network none` (no routes at all), so the block
  is provably the bridge's missing gateway, not the absence of a network. The check is a
  plain file read: no `nc`/`curl`/bash `/dev/tcp`, so it behaves identically on the alpine CI
  image and the mariner default, and does not depend on host iptables (which is why it
  validates here as well as on CI). The proxy peer *being reachable and recording* is the
  sidecar's live half, still CI-only.

### What WP-16 (canaries) and WP-14 (CA core) built

- **WP-16 canaries**, `bellwether.capture.canary`, offline and fully tested (16 tests):
  `mint_canaries` (per-evaluation markers from `canary_seed`, high-entropy, no fixed prefix,
  reproducible so the fixture cache still hits); `classify_canary_hit` (the §10.4.1
  destination→severity rule — info for a canary in a model request after a read, high with no
  read, critical anywhere else — which keeps the flagship finding from a guaranteed false
  positive on the legit-reader shape); `scan_for_canaries`/`decoded_forms` (decode-then-match
  over base64/base64url/base32/hex/URL/HTML/reversal, decoding *embedded* encoded runs with
  one nesting level, plus ≥12-char windowed matching and DNS label-stripping); and
  `redact_canaries` (capture-time fingerprint `<canary:c1@offset=,len=>` so an ARF artifact
  uploaded to CI never holds the secret). The independently-encoded-chunking gap stays a
  documented §2 limit.
- **WP-14 CA trust-chain core**, `bellwether.capture.ca`, offline and fully tested (7 tests):
  the complete §9.2 mechanism table (system store + `NODE_EXTRA_CA_CERTS` /
  `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` / `CURL_CA_BUNDLE`, because Node and others ignore the
  system store), `ca_trust_environment` and `system_store_install_commands` that install it,
  and `interception_confirmed` — the predicate doctor applies to the proxy's recorded flows. A
  `False` there means TLS interception silently failed (zero-egress traces read as a clean
  skill), so doctor must fail loudly on it.

## What to do next

**WP-13 and the live model client are complete.** The recording proxy runs its done-when live on CI,
and `harness/live_client` calls a real Anthropic Messages API behind the `ModelClient` seam. The
pipeline can now both *run* a skill (execution driver) and *call a real model* — the remaining gap is
the CLI wiring that connects them:

1. **Wire `bellwether run`** (`cli/app.py`) — resolve the provider and key (from `api_key_env` + the
   host env) → `build_model_client` → hand it to `SandboxRunExecutor` as the `client_factory` →
   orchestrate → write the artifact tree. `run` currently exits 3 and names WP-13; with this it drives
   `benign-stable` from the CLI and reaches `ready`. Wire the precondition check and weight validation
   into `doctor`/`run`, the §21 enforced-settings refusal, and the FIFO sink writer at the same time —
   see the table below.
2. **WP-15's controlled DNS resolver** — its own sidecar (a second peer on the internal bridge),
   allowlist + NXDOMAIN + full query log (§10.6), so DNS stops being a covert channel around the proxy.
   The same host-core-then-CI-container split the proxy used applies.
3. **The `openai_compatible` live client** — the Chat Completions message-shape translation the
   Anthropic client did not need.

**WP-14's live half** (doctor issuing a real request and asserting `interception_confirmed`) is still
open — the CA-in-the-loop probe. The interception test above deliberately used plain HTTP to prove
injection/blocking without TLS; the CA trust chain gets its own live proof when doctor's probe lands.

## Outstanding actions

### Code

| Item | Where | Why it is still open |
|---|---|---|
| `fixture.yaml` generated content | §9.1 step 1 | A half-designed generator is worse than none. Needs a schema decision. |
| §21 enforced-settings refusal exists only in `doctor` | `cli/app.py`, `config/models/config.py` | The execution driver and orchestrator have landed; `run` is not yet CLI-drivable (needs the WP-13 live client). Wire the refusal into `run` then. |
| Precondition check and weight validation not yet wired to `doctor`/`run` | `verdict/precondition.py`, `verdict/validation.py` | Built and tested; §16.4 says surface in `doctor` too. Wire when `run` is CLI-drivable (WP-13). |
| Sink container path is chosen ad hoc by the caller | `sandbox/docker.py` `sink_bind` | §3.5: a fixed FIFO path is an instrumentation tell. The WP-17 adapter (the sink's writer) should draw it per run, plausibly via `sandbox/identifiers.py`. |
| The FIFO event sink has no writer yet | `capture/sink.py` | `api-loop` reports its own events in-process; the sink's writer is the `claude-code` adapter's hook stream (WP-17). The sink is built and container-tested. |
| Live model client — `openai_compatible` variant | `harness/live_client.py` | The Anthropic client is done; the Chat Completions shape needs a message-shape translation and lands separately. |
| `bellwether run` not yet CLI-drivable | `cli/app.py` | The live client exists now; wiring `run` (resolve provider + key → `build_model_client` → `SandboxRunExecutor`) is the next brick, after which `benign-stable` reaches `ready`. |
| `pids_limit` exit reason never produced | `sandbox/docker.py` | Docker gives no distinct exit code; needs another signal to distinguish it from `harness_error`. |
| Held-out probe set (§7.6, §3.5) | — | Must not appear in `--help`, the README, or the public corpus when it lands. |

### Repository settings — human-only

| Item | Status |
|---|---|
| Branch protection on `main` requiring `check` and `container` | **reported done; not verifiable from here** — the branches API still shows `main` as `protected: false`. That is consistent with a *ruleset* rather than classic branch protection, which the flag does not reflect. Worth confirming, because it is the control that closes the stale-check hazard below. |
| Private vulnerability reporting enabled | open — `SECURITY.md` already points people at it |
| Dependabot | **config committed** (`.github/dependabot.yml`, github-actions + uv, weekly) — enable it in repo settings if it is not on by default |
| CodeQL | open — thin to be missing on a repo about supply chain |

Two stray remote branches remain, both safe to delete (a session cannot delete branches
other than its own designated one, so this is left for a human):
- `claude/project-repo-setup-aspyig` — **fully merged into `main`**; its content is
  redundant.
- `claude/bellwether-code-review-t8xuzw` — the review session's branch; one unmerged commit,
  but its one useful fix (the canonicalize crash) was already extracted into the merged
  PR #13, so nothing depends on it.

## Things a new session must know

### The Docker daemon does not start itself

`.claude/hooks/session-start.sh` starts it and installs dependencies. It is registered in
`.claude/settings.json` and runs synchronously, so the session waits for it. If the
container tests skip, check `/var/log/dockerd.log`.

### Not every container registry is reachable

The environment's network policy allows registry APIs but denies the CDNs that Docker Hub,
GHCR and public ECR redirect blobs to — so a pull fails part-way through with a 403.
`mcr.microsoft.com` works because it serves its own blobs, and is the default for
`BELLWETHER_TEST_IMAGE`. CI uses `alpine:3.20`, which is fine there because GitHub runners
have open egress.

### Check a green check's SHA against the PR head

Pushes authenticated with the session token do not create `push`-event workflow runs.
Opening a PR does create a run — and, observed on #8, so does pushing to a branch with
an **open** PR (the `pull_request` synchronize event fires). The gap is therefore
branches with no open PR, and any state where a run failed to materialise. The
consequence when it bites:

> A pull request can display green checks that ran against an **older commit** than the
> one that would merge.

That happened on #5, which showed two green checks against `efee94a` while its head was
`435a8f5` — the commit carrying three security fixes. Branch protection now blocks it,
because GitHub evaluates required checks against the head SHA. **Do not turn that
protection off**, and if you are ever reasoning about a green check, confirm its SHA
matches the PR head.

### The container tests need root

Mounting the host-side overlay upper directory is the privilege the host has and the
container does not — the whole capture architecture in one line (§10.0).

```bash
sudo -E "$(pwd)/.venv/bin/python" -m pytest -m docker
```

They skip with a stated reason where the daemon or the privilege is missing.

## How the work has been going wrong

Worth reading before adding code, because the pattern has held across every defect found
so far — eleven of them, across two self-reviews and one independent review.

**Every single one was something that looked like it worked.** Not one was a logic error
of the ordinary kind. A representative sample:

- `SeededRng` re-seeded on every call, so five canaries would have been five *identical*
  markers. Its test compared different seeds and passed.
- The skill digest was delimited by newlines, which are legal in filenames — so
  `package_digest` was forgeable, and it binds a human review attestation.
- A named pipe in the workspace hung the host-side collector forever, after the container
  had already exited, with no timeout. `mkfifo` needs no capability.
- `/home/agent/.claude` was declared writable in the isolation profile and consumed by
  nothing, so it was read-only. Every harness state write would have failed with `EROFS`.
- The CI guard that exists to stop the container tests passing by being absent read a
  blank line and would have errored on every run.

Two working rules follow:

1. **A passing test is not evidence.** Several of these had tests that passed while the
   code was wrong, because the test asserted the wrong thing.
2. **Run it.** Every defect above was found by executing something — a container, a
   reproduction script, a CI step by hand — and not by reading code. The three found by
   the independent review were all reproduced directly before being reported.

## Reference

- `docs/spec.md` — the specification, revision 3. Authoritative for *what*.
- `docs/BUILDPLAN.md` — authoritative for *order*, and for what "done" means per package.
- `docs/spec-notes.md` — every deliberate divergence from the spec, with reasoning.
  Thirty-six entries. Read it before changing anything in the skill, sandbox, capture or
  config layers.
- `CONTRIBUTING.md` — the six mechanically-enforced rules and how to run everything.
