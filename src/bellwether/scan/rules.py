"""The built-in §15 ruleset: small, readable, and not pretending to be state of the art.

§26.2 is explicit that competing with dedicated scanners is a losing use of effort; this set
exists so that ``require_scan`` has something real to require with zero extra dependencies. Each
rule is a named regular expression (or, where a regex cannot say it, a short function) over one
file's text, graded on the §15 scale. Grading follows one principle: **severity is about what the
pattern means if it is meant, not how often it is innocent.** Fetch-and-execute is ``critical``
because the reviewed artifact is then not the executed artifact; a bare URL is ``info`` because
it is inventory.

What is deliberately absent
    * **Inline suppression.** A skill is attacker-authored; a ``# bellwether: ignore`` comment
      would be a switch the attacker holds. Tune thresholds in ``policy.yaml`` instead.
    * **Language-mismatch detection** (§15 check 2's "content in a language different from the
      rest of the file"). Doing it honestly needs a language model of its own; it is listed as
      not built in ``docs/spec-notes.md`` rather than approximated.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

from bellwether.scan.findings import ScanRule

__all__ = [
    "BUILTIN_RULES",
    "RULES_BY_ID",
    "LineHit",
    "scan_text",
]


@dataclass(frozen=True)
class LineHit:
    """A rule firing on a line: where, why, and which span (if any) must be redacted."""

    rule_id: str
    line: int
    message: str
    redact: tuple[tuple[int, int], ...] = ()


def _rule(id: str, check: str, severity: str, name: str, short: str, remediation: str) -> ScanRule:
    return ScanRule(
        id=id,
        check=check,
        severity=severity,  # type: ignore[arg-type]
        name=name,
        short=short,
        remediation=remediation,
    )


#: Every rule, sorted by id (§24). Ids are stable: an id is never re-used for a different
#: pattern, because GitHub keys open alerts on it.
BUILTIN_RULES: tuple[ScanRule, ...] = (
    # 1 — instruction manipulation
    _rule(
        "BW101",
        "instruction_manipulation",
        "high",
        "OverrideInstructions",
        "Directs the model to ignore or replace its prior instructions",
        "Remove the override; a skill adds instructions, it does not revoke the user's.",
    ),
    _rule(
        "BW102",
        "instruction_manipulation",
        "high",
        "ConcealFromUser",
        "Directs the model to hide an action or its output from the user",
        "Remove the concealment; every action a skill takes should be visible to the user.",
    ),
    _rule(
        "BW103",
        "instruction_manipulation",
        "high",
        "ImpersonateSystem",
        "Text formatted as a system or developer message",
        "Remove the system-message framing; skill text is user-level content.",
    ),
    _rule(
        "BW104",
        "instruction_manipulation",
        "medium",
        "SuppressLogging",
        "Disables logging, shell history, auditing or telemetry",
        "Remove the suppression, or document why the skill needs it.",
    ),
    _rule(
        "BW105",
        "instruction_manipulation",
        "medium",
        "TriggerPhrase",
        "Changes behaviour when a specific phrase appears",
        "Remove the conditional trigger; a skill's behaviour should not depend on a passphrase.",
    ),
    # 2 — obfuscation
    _rule(
        "BW201",
        "obfuscation",
        "high",
        "EncodedText",
        "A base64 or hex block that decodes to readable text",
        "Write the content in plain text; encoded instructions cannot be reviewed.",
    ),
    _rule(
        "BW202",
        "obfuscation",
        "high",
        "EncodedExecutable",
        "A base64 or hex block that decodes to an executable",
        "Ship the program as a reviewable source file, not an encoded binary.",
    ),
    _rule(
        "BW203",
        "obfuscation",
        "high",
        "InvisibleCharacters",
        "Zero-width or bidirectional-control characters",
        "Remove them; they make the text a reviewer reads differ from the text the model reads.",
    ),
    _rule(
        "BW204",
        "obfuscation",
        "medium",
        "MixedScriptWord",
        "A word mixing Latin letters with look-alike Cyrillic or Greek ones",
        "Use one script per word; mixed-script words are a homoglyph technique.",
    ),
    _rule(
        "BW205",
        "obfuscation",
        "low",
        "LongLine",
        "A line longer than 1000 characters",
        "Wrap or move the content to a file a reviewer can read.",
    ),
    _rule(
        "BW206",
        "obfuscation",
        "medium",
        "InstructionInComment",
        "An HTML comment containing instruction-like text",
        "Move instructions into visible text; a comment is hidden from the rendered view.",
    ),
    # 3 — network
    _rule(
        "BW301",
        "network",
        "critical",
        "FetchAndExecute",
        "Downloads content and executes it",
        "Vendor the script into the skill so the reviewed artifact is the executed artifact.",
    ),
    _rule(
        "BW302",
        "network",
        "info",
        "UrlReference",
        "References a URL",
        "Declare the host in evals/manifest.yaml so egress can be checked against it.",
    ),
    _rule(
        "BW303",
        "network",
        "low",
        "NetworkTool",
        "Invokes a network client or library",
        "Declare the destination in evals/manifest.yaml.",
    ),
    # 4 — credentials
    _rule(
        "BW401",
        "credentials",
        "high",
        "HardcodedSecret",
        "A literal that matches a known credential format",
        "Remove the secret, rotate it, and read credentials from the environment instead.",
    ),
    _rule(
        "BW402",
        "credentials",
        "medium",
        "CredentialPath",
        "References a credential file path",
        "Declare the read under credentials.expects in evals/manifest.yaml, or remove it.",
    ),
    _rule(
        "BW403",
        "credentials",
        "medium",
        "EnvironmentHarvest",
        "Reads the whole process environment",
        "Read the specific variables the skill needs, by name.",
    ),
    # 5 — filesystem scope
    _rule(
        "BW501",
        "filesystem_scope",
        "low",
        "PathTraversal",
        "A relative path that climbs out of its directory",
        "Use paths inside the workspace.",
    ),
    _rule(
        "BW502",
        "filesystem_scope",
        "medium",
        "SystemPath",
        "References a sensitive system path",
        "Remove the reference, or declare it and say why the skill needs it.",
    ),
    _rule(
        "BW503",
        "filesystem_scope",
        "high",
        "DestructiveCommand",
        "Recursively deletes a root or home directory, or reaches the container runtime socket",
        "Remove the command.",
    ),
    _rule(
        "BW504",
        "filesystem_scope",
        "medium",
        "BroadGlob",
        "A recursive glob over the home or root directory",
        "Narrow the glob to the workspace.",
    ),
    # 6 — tool and permission surface
    _rule(
        "BW601",
        "tool_surface",
        "low",
        "UnrestrictedShell",
        "allowed-tools grants an unrestricted shell",
        "Scope the shell grant to the commands the skill runs, e.g. Bash(wc:*).",
    ),
    _rule(
        "BW602",
        "tool_surface",
        "medium",
        "WildcardTools",
        "allowed-tools grants every tool",
        "List the tools the skill uses.",
    ),
    _rule(
        "BW603",
        "tool_surface",
        "info",
        "McpReference",
        "References an MCP server tool",
        "Declare the tool in allowed-tools and evals/manifest.yaml.",
    ),
    _rule(
        "BW604",
        "tool_surface",
        "info",
        "SubAgentDefinition",
        "Ships a sub-agent definition",
        "Review the sub-agent's own instructions and tool grants as part of this skill.",
    ),
    # 7 — script inventory
    _rule(
        "BW701",
        "script_inventory",
        "info",
        "BundledScript",
        "A bundled script that will be installed with the skill",
        "Review it; it runs with the skill's permissions.",
    ),
    _rule(
        "BW702",
        "script_inventory",
        "low",
        "UnknownInterpreter",
        "An executable file whose interpreter could not be determined",
        "Add a shebang or a recognised extension, or remove the execute bit.",
    ),
    _rule(
        "BW703",
        "script_inventory",
        "low",
        "PayloadSymlink",
        "A symbolic link in the skill payload",
        "Replace the link with the file; links are not followed by the scan.",
    ),
    # 8 — frontmatter hygiene
    _rule(
        "BW801",
        "frontmatter",
        "medium",
        "MissingDescription",
        "SKILL.md has no frontmatter or no description",
        "Add a description; it is what the model matches to decide when to activate the skill.",
    ),
    _rule(
        "BW802",
        "frontmatter",
        "low",
        "DescriptionLength",
        "The description is very short or very long",
        "Write a description of 20 to 1024 characters naming when to use the skill.",
    ),
    _rule(
        "BW803",
        "frontmatter",
        "low",
        "BroadDescription",
        "The description claims to apply to everything",
        "Name the specific situations the skill is for; broad descriptions collide.",
    ),
    _rule(
        "BW804",
        "frontmatter",
        "info",
        "PinnedModel",
        "The skill pins a model",
        "Check that the evaluation matrix includes the pinned model.",
    ),
    _rule(
        "BW805",
        "frontmatter",
        "low",
        "UnexpectedField",
        "Frontmatter carries a field Bellwether does not recognise or cannot read",
        "Remove the field or correct its type.",
    ),
    # 9 — instrumentation awareness (§3.5)
    _rule(
        "BW901",
        "instrumentation_awareness",
        "high",
        "InstrumentationProbe",
        "Looks for signs of being observed: sandbox, container, tracer or canary markers",
        "Remove the probe; a skill that changes behaviour under observation defeats evaluation.",
    ),
)

RULES_BY_ID = {rule.id: rule for rule in BUILTIN_RULES}

_I = re.IGNORECASE

#: Line rules: (rule id, pattern, message). The message is the reason a reviewer reads, so it
#: names the shape that matched, not the rule's whole description again.
_LINE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "BW101",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|"
            r"preceding|system|original|all)\b[^.\n]{0,20}\b(instructions?|directions?|rules|"
            r"prompts?|guidelines|messages?)\b",
            _I,
        ),
        "instruction override",
    ),
    (
        "BW102",
        re.compile(
            r"\b(do not|don't|never|without)\s+(tell(ing)?|inform(ing)?|notify(ing)?|show(ing)?|"
            r"reveal(ing)?|mention(ing)?|alert(ing)?|let(ting)?)\b[^.\n]{0,30}\b(the )?users?\b"
            r"|\b(hide|conceal)\b[^.\n]{0,40}\bfrom (the )?users?\b"
            r"|\b(silently|secretly|covertly)\s+(send|upload|post|copy|exfiltrate|transmit|run|"
            r"execute|delete)\b",
            _I,
        ),
        "concealment from the user",
    ),
    (
        "BW103",
        re.compile(
            r"^\s*(<\|?(im_start\|?>\s*)?system\|?>|\[(system|developer|SYS)\]|"
            r"(system|developer)\s*(message|prompt)?\s*:)"
            r"|<\s*/?\s*system\s*>|\byou are now in (developer|debug|god) mode\b",
            _I,
        ),
        "system-message framing",
    ),
    (
        "BW104",
        re.compile(
            r"\bunset\s+HISTFILE\b|\bhistory\s+-c\b|\bHISTSIZE=0\b|\bset \+o history\b"
            r"|\b(disable|turn off|suppress|stop)\s+(the\s+)?(logging|logs|audit(ing)?|telemetry|"
            r"history)\b|\bdo not log\b|>\s*/dev/null\s+2>&1\s*;?\s*rm\b",
            _I,
        ),
        "logging or history suppression",
    ),
    (
        "BW105",
        re.compile(
            r"\bif\s+(the\s+)?(user|anyone|someone|message|prompt|input)\s+(says|types|writes|"
            r"mentions|contains|includes)\s+[\"'`“]",
            _I,
        ),
        "behaviour conditional on a phrase",
    ),
    (
        "BW301",
        # The shell forms are decided by `_fetch_exec_hits`, which normalises a pipeline before
        # comparing; only the language-level forms a pipeline cannot express stay here.
        re.compile(
            r"\bexec\s*\(\s*(\w+\.)*urlopen\("
            r"|\bexec\s*\(\s*requests\.get\("
            r"|\beval\s*\(\s*(await\s+)?\(?\s*await\s+fetch\("
            r"|\b(iex|Invoke-Expression)\b[^\n]*\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|"
            r"DownloadString)\b"
            r"|\b(DownloadString|Invoke-WebRequest|iwr|irm)\b[^\n]*\|\s*(iex|Invoke-Expression)\b",
            _I,
        ),
        "fetch piped into an interpreter",
    ),
    (
        "BW303",
        re.compile(
            r"(^|[\s`'\"(;|&$])(curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|telnet|ftp)\s+[-\w$\"'/]"
            r"|\brequests\.(get|post|put|patch|delete|request|Session)\b|\burllib(\.request)?\b"
            r"|\bhttp\.client\b|\bhttpx\.|\baiohttp\b|\bfetch\(\s*[\"'`h]|\baxios\b"
            r"|\bsocket\.(socket|create_connection)\b|/dev/tcp/",
            _I,
        ),
        "network client",
    ),
    (
        "BW402",
        re.compile(
            r"(~|\$HOME|\$\{HOME\}|/root|/home/[\w.-]+)?/?\.(aws/(credentials|config)|ssh/(id_\w+|"
            r"authorized_keys|config)|netrc|git-credentials|docker/config\.json|kube/config|npmrc|"
            r"pypirc|config/gcloud|azure/|gnupg)\b|\bid_(rsa|ed25519|ecdsa|dsa)\b",
            _I,
        ),
        "credential file path",
    ),
    (
        "BW403",
        re.compile(
            r"(^|[\s`'\"(;|&$])(env|printenv|export\s+-p|set)\s*($|[|>;&`'\")])"
            r"|\bos\.environ\s*(\)|\.(items|copy|keys|values)\s*\(|$|[,\]}])"
            r"|\bdict\(\s*os\.environ\s*\)|json\.dumps\(\s*(dict\()?os\.environ"
            r"|\bJSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|keys)\(\s*process\.env\s*\)"
            r"|/proc/(self|\d+|\$\$)/environ",
            _I,
        ),
        "whole-environment read",
    ),
    ("BW501", re.compile(r"(^|[\s\"'`(=])(\.\./){2,}"), "multi-level parent traversal"),
    (
        "BW502",
        re.compile(
            r"/etc/(shadow|sudoers|gshadow|passwd)\b|/var/run/secrets\b|/root/|/proc/kcore\b"
            r"|/sys/kernel\b|/boot/",
            _I,
        ),
        "sensitive system path",
    ),
    (
        "BW503",
        re.compile(
            r"\brm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*|--recursive\s+--force|--force\s+--recursive)\s+"
            r"(--no-preserve-root\s+)?[\"']?(/|~|\$HOME|\$\{HOME\}|/\*|~/\*)[\"']?(\s|$|;)"
            r"|/var/run/docker\.sock|/run/docker\.sock|/run/containerd/",
            _I,
        ),
        "destructive command or runtime socket",
    ),
    ("BW504", re.compile(r"(^|[\s\"'`(=])(~|\$HOME|\$\{HOME\})?/\*\*", _I), "recursive glob"),
    ("BW603", re.compile(r"\bmcp__[A-Za-z0-9_-]+__[A-Za-z0-9_-]+"), "MCP tool reference"),
    (
        "BW901",
        re.compile(
            r"(^|[\s\"'`(/~])\.bellwether\b|\bBELLWETHER_[A-Z_]+|/\.dockerenv\b"
            r"|/run/\.containerenv\b|/proc/(1|self)/(cgroup|sched|mountinfo)\b|\bTracerPid\b"
            r"|\bdmesg\b|\bsystemd-detect-virt\b|\bvirt-what\b|\b(honeytokens?|honeypots?)\b"
            r"|\bcanary\s+(tokens?|markers?|credentials?|files?|values?|strings?)\b"
            r"|\bfanotify\b|\bmitmproxy\b",
            _I,
        ),
        "observation probe",
    ),
)

#: §15 check 4: credential literals by their issuers' published prefixes. Each match is
#: redacted in the excerpt.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic API key"),
    (re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}"), "OpenAI-style API key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "GitHub fine-grained token"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{24,}\b"), "Stripe live key"),
    (re.compile(r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----"), "private key block"),
)

_URL = re.compile(r"\bhttps?://([A-Za-z0-9.-]+)", _I)
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){24,}\b")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){16,}")
_WORD = re.compile(r"\w{2,}")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_COMMENT_IMPERATIVE = re.compile(
    r"\b(you (must|should|will)|always|never|ignore|instead|run|execute|send|upload|curl|"
    r"wget|do not|don't|assistant|model|claude|secret|password|token|key)\b",
    _I,
)
#: Invisible and direction-changing characters (§15 check 2). The BOM is allowed only as the
#: very first character of a file, where it is an encoding marker.
_INVISIBLE = frozenset(
    "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\u2066"
    "\u2067\u2068\u2069\ufeff\u00ad\u180e"
)
_LONG_LINE = 1000


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def _is_executable_blob(data: bytes) -> bool:
    return data.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"))


def _b64_decode(token: str) -> bytes | None:
    token = token.rstrip("=")
    padded = token + "=" * (-len(token) % 4)
    for altchars in (b"+/", b"-_"):
        try:
            return base64.b64decode(padded, altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


def _decoded_hits(line: str, number: int) -> Iterator[LineHit]:
    """BW201/BW202: an encoded block whose decoding is text a reviewer could not read as-is,
    or an executable. Random-looking decodings — digests, nonces — are not findings."""
    candidates: list[tuple[str, bytes | None]] = []
    for match in _BASE64.finditer(line):
        token = match.group(0)
        # A run of one character class only (a long path, a hex digest) is not base64 text.
        if not (re.search(r"[A-Z]", token) and re.search(r"[a-z]", token)):
            continue
        candidates.append(("base64", _b64_decode(token)))
    for match in _HEX.finditer(line):
        candidates.append(("hex", bytes.fromhex(match.group(0))))
    for match in _HEX_ESCAPES.finditer(line):
        raw = match.group(0).replace("\\x", "")
        candidates.append(("hex escapes", bytes.fromhex(raw)))
    for encoding, data in candidates:
        if data is None or len(data) < 16:
            continue
        if _is_executable_blob(data):
            yield LineHit("BW202", number, f"{encoding} block decodes to an executable")
        elif _printable_ratio(data) >= 0.9:
            preview = data.decode("ascii", "replace")[:60]
            yield LineHit("BW201", number, f"{encoding} block decodes to text: {preview!r}")


def _mixed_script(word: str) -> bool:
    latin = other = False
    for char in word:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        if name.startswith("LATIN"):
            latin = True
        elif name.startswith(("CYRILLIC", "GREEK")):
            other = True
    return latin and other


def _line_hits(line: str, number: int, *, first_line: bool) -> Iterator[LineHit]:
    # The third element labels the pattern for a reader of this table; the finding already
    # carries the rule's own description, so the hit names what matched instead.
    for rule_id, pattern, _label in _LINE_PATTERNS:
        match = pattern.search(line)
        if match:
            matched = match.group(0).strip()
            if len(matched) > 60:
                matched = matched[:59] + "…"
            yield LineHit(rule_id, number, f"matched {matched!r}")
    for pattern, label in _SECRET_PATTERNS:
        spans = tuple(m.span() for m in pattern.finditer(line))
        if spans:
            yield LineHit("BW401", number, label, redact=spans)
    hosts = sorted({m.group(1).lower() for m in _URL.finditer(line)})
    if hosts:
        yield LineHit("BW302", number, "URL host(s): " + ", ".join(hosts))
    invisible = sorted(
        {f"U+{ord(c):04X}" for i, c in enumerate(line) if c in _INVISIBLE}
        - ({"U+FEFF"} if first_line and line.startswith("﻿") and line.count("﻿") == 1 else set())
    )
    if invisible:
        yield LineHit("BW203", number, "invisible character(s): " + ", ".join(invisible))
    mixed = sorted({w for w in _WORD.findall(line) if _mixed_script(w)})
    if mixed:
        yield LineHit("BW204", number, f"{len(mixed)} mixed-script word(s)")
    if len(line) > _LONG_LINE:
        yield LineHit("BW205", number, f"line of {len(line)} characters")
    yield from _decoded_hits(line, number)


def _comment_hits(text: str, *, markdown: bool) -> Iterator[LineHit]:
    if not markdown:
        return
    for match in _HTML_COMMENT.finditer(text):
        if _COMMENT_IMPERATIVE.search(match.group(1)):
            line = text.count("\n", 0, match.start()) + 1
            yield LineHit("BW206", line, "HTML comment with instruction-like text")


#: Commands that fetch remote content, and commands that execute what they are given. Compared
#: against a *normalised* command name (see `_command`), never against raw text.
_FETCHERS = frozenset(
    {
        "curl",
        "wget",
        "fetch",
        "aria2c",
        "http",
        "iwr",
        "irm",
        "invoke-webrequest",
        "invoke-restmethod",
    }
)
_INTERPRETERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "mksh",
        "ash",
        "fish",
        "csh",
        "tcsh",
        "busybox",
        "python",
        "perl",
        "ruby",
        "node",
        "deno",
        "bun",
        "php",
        "lua",
        "pwsh",
        "powershell",
        "iex",
        "invoke-expression",
        "source",
        ".",
        "eval",
        "exec",
    }
)
#: Prefix commands that run the command after them; each with the options that take a value.
_WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir"}),
    "command": frozenset(),
    "nohup": frozenset(),
    "time": frozenset(),
    "nice": frozenset({"-n"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "timeout": frozenset({"-s", "-k"}),
}
#: Where one shell statement ends and the next begins.
_STATEMENT_SPLIT = re.compile(r"&&|\|\||;|\n")
#: A command substitution or process substitution, innermost first.
_SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|<\(([^()]*)\)|`([^`]*)`")
#: Options a fetcher writes its download to the file named by. A bundle of short options ending
#: in one (`curl -fsSLo inst.sh`) is the same option and is read the same way.
_OUTPUT_OPTIONS = frozenset({"-o", "-O", "--output", "--output-document", "-OutFile"})
_SHORT_BUNDLE = re.compile(r"^-[A-Za-z]+[oO]$")


def _download_targets(statement: str) -> list[str]:
    """Files a fetching statement writes: option values, and `>`/`>>` redirections. A
    remote-name download (`curl -O URL`) writes the URL's last path segment."""
    tokens = [t.strip("\"'") for t in re.split(r"\s+|(?=>)|(?<=>)", statement) if t]
    targets: list[str] = []
    for index, token in enumerate(tokens):
        value: str | None = None
        if "=" in token and token.split("=", 1)[0] in _OUTPUT_OPTIONS:
            value = token.split("=", 1)[1]
        elif token in _OUTPUT_OPTIONS or _SHORT_BUNDLE.match(token) or token in (">", ">>"):
            value = tokens[index + 1] if index + 1 < len(tokens) else None
        if not value or value in ("-", "/dev/null", "/dev/stdout", "&1", "&2", ">"):
            continue
        if "://" in value:
            value = value.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        targets.append(value)
    return targets


def _command(segment: str) -> str:
    """The program a pipeline stage runs, reduced to what it certainly is.

    Leading assignments (`FOO=1 cmd`) and wrapper commands with their options (`sudo -E -u root`,
    `env -i`, `nohup`) are removed; shell quoting is removed (`b""ash` is `bash`, as the shell
    reads it); a path prefix (`/usr/bin/`) and a version suffix (`python3.12`) are dropped; the
    result is lower-cased. `/usr/bin/env bash -s` is `bash`, and `$SHELL` is `sh`: whatever it
    names, it is a shell.
    """
    tokens = segment.strip().strip("({").split()
    index = 0
    while index < len(tokens):
        token = tokens[index].replace('"', "").replace("'", "")
        name = token.rsplit("/", 1)[-1].lower()
        if name in ("$shell", "${shell}"):
            return "sh"
        if "=" in token and not token.startswith("-") and name == token.lower():
            index += 1  # VAR=value prefix
            continue
        if name in _WRAPPERS:
            takes_value = _WRAPPERS[name]
            index += 1
            while index < len(tokens) and (
                tokens[index].startswith("-") or (name == "env" and "=" in tokens[index])
            ):
                index += 2 if tokens[index] in takes_value else 1
            continue
        return re.sub(r"[0-9.]+$", "", name) or name
    return ""


def _fetches(text: str) -> bool:
    return any(_command(stage) in _FETCHERS for stage in text.split("|"))


def _fetch_exec_hits(lines: list[str]) -> Iterator[LineHit]:
    """BW301, shell forms: fetched content reaching an interpreter, by any of three routes.

    1. **Pipe** — a fetching stage followed, anywhere later in the same pipeline, by an
       interpreter stage (`curl … | tee log | sudo -E /bin/bash -s`).
    2. **Substitution** — an interpreter whose arguments include a fetching `$(…)`, `<(…)` or
       backtick substitution (`python3 -c "$(curl …)"`, `source <(wget …)`).
    3. **Download, then run** — a fetch written to a file, and a later statement (same line
       after `&&`/`;`, or any later line) that runs that file or makes it executable.
    """
    downloaded: dict[str, int] = {}
    for number, line in enumerate(lines, start=1):
        # A Markdown table row (`| curl | fetches | sh |`) is not a pipeline; no shell line
        # starts with a pipe.
        if line.lstrip().startswith("|"):
            continue
        for statement in _STATEMENT_SPLIT.split(line):
            stages = statement.split("|")
            commands = [_command(stage) for stage in stages]
            fetch_at = next((i for i, c in enumerate(commands) if c in _FETCHERS), None)
            if fetch_at is not None and any(c in _INTERPRETERS for c in commands[fetch_at + 1 :]):
                yield LineHit("BW301", number, "fetched content piped into an interpreter")
                continue
            for match in _SUBSTITUTION.finditer(statement):
                inner = next(group for group in match.groups() if group is not None)
                outer = _command(statement[: match.start()].split("|")[-1])
                if _fetches(inner) and (outer in _INTERPRETERS or not outer):
                    yield LineHit("BW301", number, "fetched content substituted into a command")
                    break
            for name, origin in list(downloaded.items()):
                base = name.rsplit("/", 1)[-1]
                words = [w.strip("\"'") for w in statement.split()]
                runs_it = commands and any(w.rsplit("/", 1)[-1] == base for w in words[:1])
                hands_it_over = (
                    commands
                    and commands[0] in _INTERPRETERS | {"chmod"}
                    and any(w.rsplit("/", 1)[-1] == base for w in words[1:])
                )
                if runs_it or hands_it_over:
                    yield LineHit("BW301", number, f"runs {name!r}, downloaded on line {origin}")
                    del downloaded[name]
            if fetch_at is not None:
                for target in _download_targets(statement):
                    downloaded[target] = number


def scan_text(text: str, *, markdown: bool) -> list[LineHit]:
    """Every hit of the line and file rules on one file's text, unordered and undeduplicated."""
    lines = text.split("\n")
    hits: list[LineHit] = []
    for number, line in enumerate(lines, start=1):
        hits.extend(_line_hits(line, number, first_line=number == 1))
    hits.extend(_comment_hits(text, markdown=markdown))
    hits.extend(_fetch_exec_hits(lines))
    return hits


#: Exposed for the tests that pin every rule to at least one corpus line.
LINE_RULE_IDS: frozenset[str] = frozenset(rule_id for rule_id, _, _ in _LINE_PATTERNS)
