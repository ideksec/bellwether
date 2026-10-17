# Recorded scanner output

Real SARIF written by real scanners, kept so the delegation tests (§15) read what a tool actually
emits rather than what a test author assumed it emits. Recording one already paid for itself:
Gitleaks sets no `level` (so SARIF's default `warning` grades a leaked token `medium`), and when
given an absolute path inside a volume mounted somewhere else it reports the *container's* path
for every file. Both shaped the design
(`gates.static.scanner_min_severity`; the same-path mount in `bellwether-scan.yml`).

| File | Tool | How it was produced |
|---|---|---|
| `gitleaks-8.24.3-relative.sarif` | Gitleaks 8.24.3 (`ghcr.io/gitleaks/gitleaks@sha256:e1b35e12…`) | `docker run -v "$PWD:$PWD:ro" -w "$PWD" … dir skills --report-format sarif` over a scratch repo holding `skills/demo/SKILL.md` with a fake GitHub token on line 5 |
| `gitleaks-8.24.3-container-paths.sarif` | the same | the same scratch repo mounted at `/repo` and scanned as `dir /repo` (an absolute path under a foreign mount) — every URI is a container path |

Edited after recording, and only this: the driver's ~200 rules are trimmed to the one used plus
two others, and each result's `snippet` (which held the token) is replaced with `<SECRET>`, so no
secret-shaped string is committed. The tests inject a fake secret into the snippet at run time.
