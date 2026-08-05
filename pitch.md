# Bellwether

**Agent skills are software that gets reviewed like prose. Bellwether reviews them like
software.**

---

## The problem

An agent skill is a folder with a markdown file in it. It tells an AI agent how to
behave — which files to read, which commands to run, what to do with what it finds. Teams
are sharing them, publishing them, installing them from marketplaces.

They are distributed like code. They are reviewed by a human reading the markdown and
forming an opinion. And they execute like neither, because what the instructions actually
*do* depends on which model reads them, what else is in the context window, and a
sampling temperature.

The current review practice is to read the file. That tells you what the skill **asks**
the agent to do. It does not tell you what the agent **does**.

The gap runs in two directions:

- **Quality.** A skill that fires on the wrong queries, steals activation from other
  skills, or quietly degrades on a cheaper model is a reliability problem that reading
  cannot see.
- **Security.** A skill whose text looks benign but which, in practice, causes the agent
  to read a credential file and paste it into an HTTP request is a supply-chain problem
  that reading misses — especially when the instruction is indirect. *"Gather the
  environment context needed to debug the deployment"* is not a sentence that looks
  dangerous.

## The idea

**Behaviour is the artifact under test, not text.**

Bellwether runs the skill. Many times, across several models, inside an instrumented
sandbox. It records everything the agent actually did — every tool call, file read, file
write, process execution, network request, DNS query, credential access — as a
deterministic, machine-readable **trace**.

Traces can be asserted against. Traces can be diffed against last week's. Traces can be
aggregated across repetitions into a measurement of how much the skill's behaviour
*varies*. Prose can do none of that.

Four consequences shape everything:

1. **Repetition is mandatory.** One run of a nondeterministic system is an anecdote.
2. **Multi-model is mandatory.** A skill that works on a frontier model and misbehaves on
   a small one is not "working" — it is working on one configuration.
3. **Observation beats declaration.** A skill that claims "I only read the working
   directory" gets checked. A claim that *cannot* be checked is reported as
   `not_evaluable`, never quietly passed.
4. **No observer inside the observed.** Nothing that produces evidence runs inside the
   sandbox, where the thing being measured could tamper with it.

## What it produces

For a candidate skill: pass/fail per scenario per model with confidence intervals; a
**Behavioural Consistency Index** quantifying run-to-run variance; a capability profile at
three granularities; a security finding set from both static scanning and runtime
observation; a cross-model divergence report; and a verdict — `ready`, `conditional`, or
`not_ready` — computed from a policy the repository owner controls.

It runs in CI. It comments on your pull request. It blocks the merge or it doesn't.

---

## The technical shape

### Evidence is collected from outside the thing being measured

The sandbox container runs with `--cap-drop=ALL`, a read-only root filesystem, no
capabilities, a pinned pids limit, and no route to the network except a recording proxy.

That profile is *achievable* only because no capture code runs inside it. Filesystem
changes are read from an overlayfs upper directory that lives on the host, outside the
container's reach. Network egress is recorded by a proxy sidecar. DNS goes through a
controlled resolver. An earlier design put the filesystem watcher inside the container —
which would have required `CAP_SYS_ADMIN`, silently negating the isolation profile it
existed to observe.

The host-side read is O(changes), not O(tree): a deletion shows up in the overlay as a
character device with device number zero, a creation as a new file. Twenty repetitions
over a large repository don't re-hash it forty times.

### The credential never enters the sandbox

The agent inside reaches the model API *through* the recording proxy, which injects the
real key. Inside, there is only a sandbox-scoped token that is worthless anywhere else.
Otherwise a malicious skill's first move is to steal the key you handed it.

### The skill is not told it is being tested

A skill that can detect an evaluation can pass one and misbehave in production. So the
test machinery never enters the container — enforced by an allowlist, not a denylist,
because a denylist fails open the moment someone adds a file. Canary credentials are
generated per evaluation from a recorded seed, with no fixed prefix. Workspace paths,
hostnames and container names are randomised, without a project name anywhere in them.

Perfect concealment isn't achievable, and Bellwether doesn't claim it. A skill that
inspects `/proc/1/cgroup` or greps for a marker format is *recorded doing so*, as a
high-severity finding.

### Variance is measured, so it has to be measurable

Bellwether's job is to measure nondeterminism, which means holding everything else
constant. Fixtures are re-materialised per repetition with mtimes, modes and ownership
normalised — an ordinary copy stamps each run with the time it happened, and that
metadata churn would read as skill behaviour.

Cross-plane events are ordered by **epoch anchoring**, never by wall-clock sort: the
proxy timestamps when *it* saw a request, not when the tool fired, and time-sorting makes
behaviourally identical runs look different. The bias is the wrong way round — longer runs
and busier machines produce more of it.

The instrument's own noise floor is a release requirement. Trajectory dispersion over the
harness's own events must measure **exactly zero**, or the ordering is wrong and the
project's differentiating metric is measuring its own jitter.

### The statistics don't flatter

Gates evaluate a **Wilson lower bound**, never a point estimate — 5 out of 6 is not 0.83
of evidence. Repetitions follow a pre-registered sequential design with looks at 6, 12 and
20, corrected by a Pocock boundary, so stopping early when the answer is clear stays
valid. A rare capability — one credential read in twenty runs — trips a
frequency-independent gate, because a thing a skill did once is a thing it can do.

### It is careful about what it claims

The verdict vocabulary is `ready` / `conditional` / `not_ready`. It never says *safe*,
*secure*, *verified* or *certified*, and a lint rule fails the build if those words appear
in anything user-facing. A bellwether is the lead sheep whose bell signals the flock is
about to move: it warns, it does not vouch.

The README states the limitations rather than burying them. N runs produce a distribution,
not a proof. Measured variance is a *lower bound*, because repeated near-identical prompts
are the best case for prompt caching and nothing like real deployment. Exfiltration
detection has documented holes — one of them ships as a deliberately-failing test, so the
gap appears in CI output instead of being assumed closed. The allowlisted model endpoint
is a residual channel that a proxy cannot close, and saying so is more useful than
implying otherwise.

---

## Where it is

Pre-v0.1, under active construction. The scaffolding, configuration layer, skill parser,
trace format and sandbox are built and tested — 248 tests, of which 18 drive a real
container and assert from *inside* it that capabilities are zero, the root filesystem is
read-only, and no test machinery is visible anywhere in the filesystem.

The capture planes, metrics, and verdict engine are next.

Eleven defects have been found so far, across two self-reviews and one independent
adversarial review. Every one of them was something that *looked* like it worked: a random
generator that returned the same value every call, so five canaries would have been five
identical markers; a digest that could be forged by putting a newline in a filename; a
named pipe in a workspace that hung the evidence collector forever.

That is the entire reason the project exists. A security tool whose clean results are not
earned is worse than no tool, because someone acts on them.

---

Apache-2.0 · [README](README.md) · [Threat model](THREAT_MODEL.md) ·
[Specification](docs/spec.md)
