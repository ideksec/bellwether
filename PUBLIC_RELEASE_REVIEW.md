# Bellwether — public-release readiness review

**Reviewer stance:** independent and adversarial. The repository was treated as a target: claims were
verified against the implementation, not the docs, and the pass hunted specifically for the project's
own signature failure mode — *a broken observation or control path that produces a reassuring-looking
clean result.* Where a control was reachable and false-green, it was fixed with a regression test that
fails before the fix; where enforcement is genuinely still roadmap breadth, it is disclosed in the
tool and the docs rather than concealed.

**Scope of this review:** technical architecture, security (repo as adversarial target), engineering
quality including test realism, public-release hygiene, and career/portfolio optics.

**Method.** Two passes. The first was targeted — parallel subsystem reviews with every reported issue
reproduced by running code. The second read **every documentation file end to end** (8,400 lines
across 14 documents, including the 3,790-line specification) rather than grepping for known risks,
and exercised the live CLI path directly: `--help`, `init`, `doctor` on a fresh scaffold, the
unimplemented-command refusals, and `bellwether run` itself. The systematic read is what found BW-51
and BW-52 — neither was reachable from a targeted search, because both are *contradictions between
documents* or *absences*, and you cannot grep for a caller that does not exist.

**One limit, stated plainly:** no paid model run was executed. This environment holds no
`ANTHROPIC_API_KEY` (Claude Code authenticates by OAuth token, which is not a key Bellwether can
use), so the live-model half of `bellwether run` could not be exercised here. Everything below the
model was: the real container suite, the sandbox, the CLI, and the full offline pipeline. The
end-to-end live claim therefore rests on the prior CI evidence, not on a run performed during this
review — which is why §4 reports it as CI-proven rather than reviewer-verified.

**Baseline at review time:** commit on `claude/codebase-security-quality-review-2q75hv`, pre-v0.1,
Apache-2.0. All six mechanical gates green; 834 offline tests pass; 45 docker tests pass, 6 CI-only
skip; `PYTHONHASHSEED=12345` byte-stable; `bellwether demo` regenerates its committed reports with no
diff; full-history secret scan clean.

---

## 1. Executive assessment

Bellwether is a CI/CD gate for AI-agent *skills*: it runs a candidate skill N times in a hardened
sandbox behind a dual-homed recording proxy, captures what the agent actually did across several
evidence planes, measures how consistent that behaviour is, and renders a `ready` / `conditional` /
`not_ready` verdict backed by inspectable evidence. Its thesis is deliberately humble and stated in
the name — *a bellwether warns; it does not vouch* — a strong regression gate and a weak assurance
gate. That restraint is the project's most valuable property, and it survives scrutiny: the language
lint mechanically bans proof-vocabulary in user-facing strings, and the report footer states the
limitations verbatim.

The codebase is unusually disciplined for a prototype: a mechanically-enforced acyclic module
layering, `mypy --strict` over the whole package, deterministic artifacts that are byte-compared in
tests, supply-chain pinning enforced by a custom lint, and a documented divergence log
(`spec-notes.md`) that reads like a staff engineer's design journal. The crown-jewel security
invariants — no observer inside the sandbox, no unmediated route out, real credential never in the
container, deterministic redacted trace — were inspected and hold.

The one thing that most needed finding, I found: **the live verdict path under-enforced relative to
what the demo and the policy imply.** The declared-scope check rendered a green "within scope" for
every live run without ever running the check (a skill could use a manifest-denied tool and still
reach `ready`). That is precisely the target bug class, and it is now fixed on the live path with a
differential regression test. Two smaller reachable gaps were closed (an egress canary case-fold
miss; a family of policy dispositions that read as active controls but do not gate), the latter by
making the tool disclose the boundary in `doctor` rather than by overclaiming enforcement it does not
yet have.

A second, systematic pass — reading every document end to end rather than searching for known risks —
found the same pattern once more: **the §16.4 precondition check is built, exported, unit-tested, and
called from nowhere** (BW-51). It fails safe, so it is a wasted-spend and spec-compliance problem
rather than an unearned verdict, and it is disclosed rather than hastily wired. That pass also found
four places where two project documents contradicted each other — including the live example telling
a user the recording proxy "is not yet wired" while its own config turns it on (BW-52). Those are
fixed. The recurrence is worth naming honestly: *built, tested, never wired* is this codebase's
characteristic defect, and the review's main contribution is finding three more instances of it.

**Recommendation: publish as an explicitly experimental, pre-v0.1 portfolio project.** It is credible
precisely because it does not oversell — the remaining gaps are roadmap breadth, disclosed in three
places (`README`, `THREAT_MODEL`, `doctor`). See §10 for the verdict.

---

## 2. Changes made in this review

All changes are on the review branch, as coherent commits, each with tests where code changed.

| # | Commit | What | Why |
|---|--------|------|-----|
| 1 | release hygiene | `.gitleaks.toml` (allowlists the two canary templates only), `.gitignore` secret patterns (`.env*`, `*.pem/*.key/*.p12/*.pfx`, `secrets/`), `pyproject` author → **Greg Weir**, project URLs → intended `ideksec/bellwether` | public-release hygiene |
| 2 | scope enforcement (BW-47) | thread the manifest's `declared_scope` through `drive_evaluation` as a declared-vs-observed table, decoupled from the still-stubbed network/write derivations | close the reachable false-green in the verdict path |
| 3 | egress case-fold (BW-50) | scan the egress host/SNI the way a DNS name is scanned (case-folded, label-split) since the host is recorded lowercased while a marker is mixed-case | close a subdomain-tunnel exfil the case-sensitive scan missed |
| 4 | doctor disclosure (BW-49) | `ENFORCED_SECURITY_RUNTIME_DISPOSITIONS` as the one authoritative "what gates" list; `doctor` names every configured disposition that is inert | make a captured-but-ungated control legible, never mistaken for a gate |
| 5 | docs / disclosure | `README` "what the live verdict gates today", `THREAT_MODEL` enforcement boundary, `SECURITY_QUALITY_REVIEW` public-release pass, `spec-notes` entries, `STATUS`/`pitch` refresh | disclose the boundary; record the pass |

Commit hygiene going forward: `Co-Authored-By: Claude` is preserved (the project is honest that it
was built with heavy agentic assistance — see §7), with the noisy session URLs and robot emoji
dropped. History was **not** rewritten — no cosmetic rebase, and no real secret to expunge (§5).

---

## 3. Findings by severity

Status legend: **Fixed** (closed with a regression test) · **Mitigated** (residual risk reduced /
disclosed) · **Deferred** (real, tracked, out of pre-v0.1 scope) · **Accepted** (understood, not a
defect to close).

### Critical — 0 new
No new Critical findings. The two historical Criticals from the prior review (BW-01 digest collision;
BW-02 §21 enforced-settings absent from `run`) were already fixed and were re-confirmed to still hold
this pass. The crown-jewel invariants (credential isolation, no observer inside the observed, no
unmediated route out) were exercised and hold.

### High
- **BW-47 — declared manifest scope not applied on the live `run` path. [Fixed]** The `scope` gate
  rendered `pass / within scope` from an always-empty `scope_exceeded`, so the check never ran on the
  live path — a skill could use a manifest-denied tool and reach `ready`. This is the target bug
  class (a clean-looking result from a control that did not execute). Fixed by threading
  `declared_scope` through the driver as a declared-vs-observed table, evaluated off the run outcome
  so the still-stubbed network/write derivations do not drag a clean run to `not_evaluable`.
  Regression `test_drive_evaluation_enforces_declared_scope_on_the_live_path` is differential and
  fails `() == ('read',)` against the pre-fix driver. *(The prior catalog rated this Medium; I rate
  it High because it is a reachable false-green in the verdict itself.)*

### Medium
- **BW-51 — the §16.4 precondition check is built, tested, and never called. [Disclosed, not fixed]**
  `check_preconditions` is exported from `verdict/` and covered by `tests/test_verdict.py`, but a
  grep for callers across the package returns the definition and the export and nothing else. The
  spec's "MUST refuse to start" an unsatisfiable policy/target combination never executes, so an
  unsatisfiable profile is discovered only after a full matrix has been paid for. Same
  built-tested-never-wired pattern as BW-47. **Fails safe** — the gates still block correctly on
  `not_evaluable`, so no unearned verdict is produced; the cost is wasted spend and a violated spec
  MUST. Not fixed here because wiring it needs per-target capability declarations and the runner's
  plane set threaded into `run`, and getting those wrong would make the check *refuse valid runs* —
  a worse failure than the current one, and not something to attempt at the end of a hygiene pass.
  README and STATUS previously read "verdict engine + precondition check — done"; both now
  distinguish the finished engine from the absent wiring, and `doctor` says so directly.
- **BW-49 — only `egress_outside_allowlist` drives the scored verdict. [Mitigated + Deferred]** The
  policy exposes 13 `security_runtime` dispositions and the scaffold sets most to `block`, but 12 of
  them (canary leaks, DNS-outside-allowlist, undeclared credential reads, sensitive-directory access,
  anomaly checks) are captured as evidence and never reach a gate. A `block` there reads as an active
  control while doing nothing. **Mitigated** by making `doctor` name every inert disposition, backed
  by a single authoritative `ENFORCED_SECURITY_RUNTIME_DISPOSITIONS` list; **enforcement deferred** to
  per-plane roadmap work. Regression `test_doctor_warns_that_most_runtime_dispositions_do_not_gate_yet`.

### Low
- **BW-50 — egress host/SNI canary scan missed a subdomain-tunnel exfil on a case fold. [Fixed]** A
  marker is mixed-case; `_norm_host` records the host lowercased, and the scan was case-sensitive, so
  `<marker>.attacker.com` slipped past. Fixed by scanning host/SNI case-folded and label-split (DNS
  semantics) while keeping the path case-sensitive and decode-aware. The prior test masked this by
  building the flow with an un-normalised host; it is replaced by one that records the host through
  `_norm_host` and fails `[] == ['canary_leak']` pre-fix.

- **BW-52 — documentation drift, found by reading every doc end to end. [Fixed]** Four contradictions
  where two project-owned documents disagreed, each of the kind that costs a reader trust in *both*:
  (a) `examples/live/policy.yaml` and its README said "this executor does not yet wire the recording
  proxy" while `examples/live/config.yaml` turns the proxy on and says egress *is* observed — in the
  example a user copies; (b) `docs/ci-integration.md` said a live CI run "has not yet been exercised
  end to end" while the README calls it proven; (c) `doctor` attributed missing probes to work
  packages that are **done** (WP-5, WP-6, WP-11), reading as "that work has not landed" when what is
  actually missing is the probe; (d) `bellwether scan` said the scanner lands in "WP-20 (v0.1)" while
  `doctor` said v0.2. Also fixed: CONTRIBUTING's "the full check, as CI runs it" listed five of the
  six gates (omitting `pin_lint`), `BUILDPLAN.md` referenced a `bellwether-spec.md` that does not
  exist, `CLAUDE.md` called a wired resolver "the next brick", and STATUS's live outstanding-actions
  table still said `bellwether run` was "not yet CLI-drivable".

### Info
- **Docker SDK divergence now recorded. [Fixed]** §22 names the Docker SDK; the implementation
  deliberately shells out to the `docker` CLI because the flags *are* the security boundary. The
  reasoning existed only as a `pyproject.toml` comment; the project's own rule puts a deliberate
  spec divergence in `spec-notes.md`, so it is now there.
- **Repo hygiene. [Fixed]** Project author set to Greg Weir; project-owned URLs point to the intended
  `ideksec/bellwether`; `.gitignore` blocks secret-bearing patterns; `.gitleaks.toml` allowlists only
  the two intentional canary templates. No proof-vocabulary introduced (verified: language lint
  green; prose docs are outside the lint by design).
- **Provider-subdomain scan exemption. [Accepted]** The canary scan exempts `model_api`-class
  requests and classification is suffix-matched, so in principle a provider *subdomain* inherits the
  exemption. Reachability is bounded by the default-deny allowlist and the fact that an attacker does
  not control provider subdomains, so this is a facet of the already-disclosed residual model-API
  channel, not an independent hole.

### Deferred (disclosed, not release blockers)
Network/write scope *derivations* (undeclared-egress not yet scored); wiring canary/DNS/credential
dispositions into scored gates (WP-15/16/18); the blocking static-scan gate (lands with the §15
scanner); hash-pinning the full sidecar dependency closure. All are stated in `STATUS.md`,
`THREAT_MODEL.md`, and surfaced by `doctor`.

---

## 4. Test & CI state (exact values)

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check .` | pass |
| Format | `ruff format --check .` | pass (188 files) |
| Types | `mypy` (strict, whole package) | pass (103 source files) |
| Module boundaries | `lint-imports` | 5 contracts kept, 0 broken |
| Verdict vocabulary | `tools/language_lint.py` | pass |
| Supply-chain pinning | `tools/pin_lint.py` | pass (2 workflow + 2 Dockerfile inputs pinned) |
| Offline suite | `pytest -m "not docker"` | **834 passed, 51 deselected** |
| Container suite | `sudo -E … pytest -m docker` | **45 passed, 6 skipped** (CI-only sidecar-image builds, with stated reasons) |
| Determinism | `bellwether demo` re-run | **byte-identical** — `git diff examples/` empty |

Total: **885 tests**. Every code fix in this review carries a regression test that fails before the fix
and passes after (each verified by reverting the fix inline and re-running). The 6 docker skips are
sidecar-image builds that need open egress to `pip install mitmproxy`/`dnslib`; they run on CI and
skip locally with an honest stated reason, never a silent pass.

**Live CLI path, exercised directly.** `--help`, `init` into a clean directory, `doctor` against a
fresh scaffold, every unimplemented-command refusal, and `bellwether run` itself. Findings worth
recording: the missing-key path is genuinely good — exit 3 (the correct §20 infrastructure code), a
message naming the exact environment variable, and an explanation of *why* the host holds the key and
the sandbox does not. The unimplemented commands exit 3 and name where the work lands, rather than
printing an empty result that would read as a clean run. `doctor` on a fresh scaffold surfaces the
placeholder model ids, the unpinned sandbox image, the inert runtime dispositions, and the static-scan
no-op — a good first-contact experience. Determinism re-verified this pass under `PYTHONHASHSEED`
12345 and 999: `bellwether demo` regenerates the committed reports byte-identically under both.

---

## 5. Secret & git-history audit

**Method:** full-history scan with Gitleaks 8.21.2 over `--all --full-history` (95 commits), plus a
control scan with default rules and the project allowlist removed, plus a targeted grep of the two
flagged strings across all tracked content.

**Result: no real secret in the working tree or anywhere in history.** With default rules and no
allowlist, exactly **one** finding surfaces: the `private-key` rule matching the OpenSSH-PEM canary
template at `src/bellwether/capture/planting.py:46`. That file builds *deliberately fake* credential
shapes (AWS INI, OpenSSH-PEM, `.env`, git-credentials) whose bodies wrap a random canary marker and
never real key material — this is the product's core mechanism (§10.4). The AWS string
`AKIAIOSFODNN7EXAMPLE` is Amazon's own public documentation example key, used as bait; it appears only
in `planting.py` and the allowlist that documents it.

- **`.gitleaks.toml`** allowlists exactly and only those intentional canaries (path
  `capture/planting.py` + the documented AKIA example), so a future scan surfaces only genuine
  problems. Full-history scan with the project config: **no leaks found**, exit 0.
- **No credential was exposed, so nothing needs rotation, and no history rewrite was performed.** Per
  the brief, git history is not rewritten for cosmetic reasons — only actual sensitive material would
  justify it, and there is none.
- The commit-author email is the project owner's own address; it is present only in commit metadata,
  not in tracked project content, and is the owner's deliberate choice — not a leak.

---

## 6. Public optics — five reviewer lenses

1. **A hiring manager for a security-leadership / AI-security role.** Reads the README and
   `THREAT_MODEL` first. Sees a coherent threat model, named trust boundaries, crown-jewel invariants,
   and — crucially — an explicit statement of what the tool does *not* do. The honesty reads as
   senior, not junior. Strong positive.
2. **A skeptical security engineer.** Goes looking for overclaim. Finds the language lint, the
   `not_evaluable`-beats-silent-pass discipline, the disclosed enforcement boundary, and a
   `SECURITY_QUALITY_REVIEW.md` that catalogs ~50 of the project's own defects with reproductions.
   The self-critique is the credibility.
3. **An OSS maintainer / contributor.** Finds `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
   Apache-2.0, six mechanical gates, and a clean `docs/` set. Onboarding is legible. The one-brick-one-PR
   cadence is documented.
4. **A journalist or LinkedIn skim.** Gets the one-line thesis ("it warns; it does not vouch") and a
   concrete, demoable artifact (`bellwether demo` → an HTML report). The "argument at Black Hat"
   origin story is memorable and true to the experimental framing.
5. **A future teammate inheriting the code.** Finds `STATUS.md` ("what's next"), `spec-notes.md` (why
   each divergence), and tests that byte-compare committed artifacts. The project is picked up, not
   reverse-engineered.

No lens surfaces an embarrassment: no secrets, no dead-serious overclaim, no abandoned scaffolding
presented as finished, no impersonation or fabricated authority.

---

## 7. Career-fit assessment

The project signals exactly the transition it is meant to support — from SecOps/IAM/IR/threat-intel
toward **AI Security, security architecture, and security strategy/leadership** — and it does so
without pretending to be something it is not.

- **Spots an emerging problem early.** Agent-skill supply chain is a real, under-tooled risk surface;
  Bellwether stakes out a defensible position (evidence over prose) before the field has settled.
- **Builds a coherent threat model and architecture.** The trust boundaries, the "no observer inside
  the observed" invariant, the dual-homed proxy with credential brokering, the evidence planes — this
  is architecture, not scripting.
- **Turns an idea into a working prototype with AI tools — and rigorously reviews what the agent
  produces.** This is the differentiating signal. The repository is *honest that it was built with
  heavy Claude Code assistance*, and its most valuable artifact is the adversarial self-review that
  keeps catching the agent's plausible-but-wrong output ("a control that reads correct and has a green
  test but does not run"). The reviewer, not the typist, is the author here.
- **Holds engineering discipline as a leader would demand it.** Mechanical gates, determinism,
  supply-chain pinning, language restraint — the things a security leader wants a *team* to do,
  demonstrated on their own work.

What it deliberately is **not**: a polished Python product, a finished assurance platform, or a claim
of novel research. Framing it as an experiment is the correct — and more senior — move. The honest
"here is what it does not do yet" is worth more to this audience than a false "done."

---

## 8. Remaining limitations (kept explicit)

These are pre-v0.1 realities, disclosed in the tool and docs, and are **not** release blockers:

- Enforcement breadth: only egress (and now declared tool/filesystem scope) is *scored*; canary/DNS/
  credential/directory/anomaly findings are captured and shown but not yet gated (BW-49). `doctor`
  names the inert dispositions.
- The §16.4 precondition check does not run (BW-51), so an unsatisfiable policy is discovered after
  the matrix is paid for rather than before. Fails safe; disclosed in `doctor`, README and STATUS.
- The network/write scope derivations are stubbed, so an undeclared-*egress* violation is not yet
  scored on the `run` path (the declared tool/read table is).
- The residual model-API channel cannot be closed by a proxy that must pass model traffic; it is
  disclosed, and the canary scan deliberately exempts it rather than falsely flag or falsely clear.
- Measured variance is a lower bound (near-identical prompts in close succession are the ideal case
  for provider-side caching).
- The sandbox is adequate for *observing* unknown-quality skills, not for detonating confirmed
  malware.
- Breadth still on the roadmap: the `claude-code` adapter, the coverage/noise-floor calibration
  proofs, live canaries wired into the scored path, and the v0.1 acceptance corpus.

---

## 9. Manual actions for the owner (outside this review's remit)

1. **Rename the GitHub repository** from `ideksec/bellweather` to `ideksec/bellwether` (the intended
   public spelling). The project-owned URLs already point at `bellwether`; the git remote and local
   directory keep the old spelling until you rename. *(Not done here — repo administration is yours.)*
2. **Change repository visibility to public** when ready. *(Not done here, by design.)*
3. *(Optional)* Add a copyright/attribution line — a `NOTICE` file or the Apache appendix's
   `Copyright [year] Greg Weir` — if you want explicit attribution beyond the `pyproject` author field.
   Not required for a valid Apache-2.0 release.
4. *(Optional)* If you later enable GitHub secret scanning / push protection, the two canary templates
   will flag; the committed `.gitleaks.toml` documents them, and you can mirror that allowlist in the
   platform settings.

No credential rotation is required (§5).

---

## 10. Verdict

The review set out to find the dangerous case — a control that renders a clean result without doing
its job — and it found the important one (BW-47) and fixed it, closed two smaller reachable gaps, and
made the remaining enforcement boundary legible in the tool itself rather than papering over it. The
history is clean, the gates are green, the artifacts are deterministic, and the project's defining
virtue — not overselling — is intact and, if anything, strengthened. The remaining gaps are roadmap
breadth, disclosed in three places, and appropriate for a project published as an explicit
experiment.

## READY FOR PUBLIC RELEASE

*Publish as pre-v0.1, explicitly experimental. Optimized to be credible, not to look finished — which,
for this audience, is the stronger position.*
