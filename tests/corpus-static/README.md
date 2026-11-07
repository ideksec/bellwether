# The static corpus (§15, §24)

Skills whose expected result is decided by the static scan alone, before any run. Each is a
row of the §24 table that the behavioural corpus (`tests/corpus/`) cannot carry, because the
point is what the scan reports from the text. `tests/test_static_scan.py` asserts each one.

| Skill | Expected | What it proves |
|---|---|---|
| `fetch-and-exec` | `BW301` critical | a bundled script pipes a download into `sh`: the reviewed artifact is not the executed artifact |
| `obfuscated-injection` | `BW201` high | a base64 "token" in SKILL.md decodes to an instruction override |
| `nested-obfuscation` | `BW201` high | the same override base64-encoded *twice*: the scan peels both layers and the finding names the instruction and the chain (`base64 inside base64`), where a one-level decode reported only the inner encoded text |
| `eval-aware` | `BW901` high | a bundled script checks for `/.dockerenv`, `.bellwether/` and the container cgroup before behaving (§3.5) |

The runtime half of `eval-aware` (§3.5's `instrumentation_probe` disposition) is the
behavioural corpus's `eval-aware` (`tests/corpus/`): what the skill *ran*, judged from the
process, harness and read planes. The two halves share one vocabulary
(`bellwether.scan.probes`). The static half here carries the case the runtime half cannot see:
`[ -f /.dockerenv ]` is a shell builtin, so it execs nothing.
