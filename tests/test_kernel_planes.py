"""Plane B reads and Plane D′ processes: attribution, scope, assertions (§10.2, §10.3, §12.5).

The host-side recorder reports every exec and read the kernel saw; everything after it is pure,
and is driven here end to end — :func:`kernel_plane_actions` builds the records exactly as the
executor does, a trace is written and read back, and the evidence index, the scope table, the
undeclared-process / undeclared-credential judgements and the assertion catalogue all read it.
The real recorder against a real container is ``tests/test_kernel_planes_docker.py``.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from bellwether.assertions import (
    EvidenceIndex,
    evaluate,
    evaluate_scope,
    undeclared_credential_reads,
    undeclared_processes,
)
from bellwether.capture.fanotify import (
    ExecEvent,
    ReadEvent,
    RecordedActivity,
    parse_mountinfo,
)
from bellwether.config.models.baseline import PlatformBaseline
from bellwether.config.models.manifest import DeclaredScope
from bellwether.config.models.scenarios import AssertionSpec
from bellwether.harness import ApiLoopAdapter, ClaudeCodeAdapter, HarnessProcessRules
from bellwether.harness.claude_code import ScriptedLaunch, hook_settings
from bellwether.sandbox import ZoneMap
from bellwether.trace import (
    Action,
    Coverage,
    NormalizationContext,
    PlaneCoverage,
    RunFooter,
    RunHeader,
    SandboxRef,
    SkillRef,
    TargetRef,
    TokenTotals,
    capability_for,
    kernel_plane_actions,
    kernel_plane_coverage,
    parse_trace,
    serialize_record,
)

_TS = dt.datetime(2026, 10, 9, 12, 0, 0, tzinfo=dt.UTC)
_WS = "/work/k7"
_CRED = "/home/agent/.aws/credentials"
_CTX = NormalizationContext(workspace_root=_WS)
_API_LOOP = ApiLoopAdapter.process_rules()
_HOOK = hook_settings("/run/bw/sink-x")
_CLAUDE = ClaudeCodeAdapter(ScriptedLaunch([]), settings=_HOOK).process_rules()
_HOOK_COMMAND = next(iter(_CLAUDE.subtrees))


class _Recorder:
    """Builds a :class:`RecordedActivity` the way the kernel reports one, in order."""

    def __init__(self) -> None:
        self.order = 0
        self.execs: list[ExecEvent] = []
        self.reads: list[ReadEvent] = []

    def exec(
        self, pid: int, ppid: int | None, argv: Sequence[str], exe: str | None = None
    ) -> _Recorder:
        self.order += 1
        path = exe or f"/usr/bin/{argv[0].rsplit('/', 1)[-1]}"
        self.execs.append(
            ExecEvent(
                order=self.order, ts=_TS, pid=pid, ppid=ppid, exe=path, filename=path,
                argv=tuple(argv),
            )
        )  # fmt: skip
        return self

    def read(self, pid: int, path: str) -> _Recorder:
        self.order += 1
        self.reads.append(ReadEvent(order=self.order, ts=_TS, pid=pid, path=path))
        return self

    def activity(self) -> RecordedActivity:
        return RecordedActivity(
            execs=tuple(self.execs),
            reads=tuple(self.reads),
            exec_mounts=("/", _CRED, _WS),
            read_mounts=(_CRED, _WS),
        )


def _actions(recorder: _Recorder, rules: HarnessProcessRules) -> list[Action]:
    return kernel_plane_actions(
        recorder.activity(),
        rules=rules,
        zones=ZoneMap(workspace=PurePosixPath(_WS)),
        canary_paths={_CRED: "c1"},
    )


def _index(recorder: _Recorder, rules: HarnessProcessRules) -> EvidenceIndex:
    reads, process = kernel_plane_coverage(recorder.activity(), reason_if_absent="")
    coverage = Coverage(
        harness_events=PlaneCoverage(fidelity="full"),
        credentials=PlaneCoverage(fidelity="full"),
        filesystem_reads=PlaneCoverage(
            fidelity=reads.fidelity, reason=reads.reason, domain=list(reads.domain or ())
        ),
        process=PlaneCoverage(fidelity=process.fidelity, reason=process.reason),
    )
    header = RunHeader(
        run_id="r",
        eval_id="e",
        scenario_id="s",
        repetition=1,
        skill=SkillRef(
            name="k", package_digest="sha256:" + "0" * 64, payload_digest="sha256:" + "0" * 64,
            source="test",
        ),
        target=TargetRef(harness="api-loop", provider="scripted", model_alias="frontier"),
        sandbox=SandboxRef(image="img"),
        coverage=coverage,
        started_at=_TS,
    )  # fmt: skip
    footer = RunFooter(ended_at=_TS, wall_clock_ms=1, exit_reason="completed", tokens=TokenTotals())
    lines = [serialize_record(header), *map(serialize_record, _actions(recorder, rules))]
    trace = parse_trace("\n".join([*lines, serialize_record(footer)]) + "\n")
    return EvidenceIndex.from_trace(trace, _CTX)


def _roles(recorder: _Recorder, rules: HarnessProcessRules) -> list[tuple[str, str]]:
    return [
        (str(a.action["argv0"]), str(a.action["role"]))
        for a in _actions(recorder, rules)
        if a.kind == "process_exec"
    ]


def _scope(**fields: Any) -> DeclaredScope:
    return DeclaredScope.model_validate({"network": {"egress_allow": []}, **fields})


# ---------------------------------------------------------------------------
# Attribution by tree
# ---------------------------------------------------------------------------


def test_api_loop_tools_are_the_harness_and_what_bash_runs_is_the_skill() -> None:
    """The read tool's `cat` and the bash tool's `sh` are tool implementations (top-level); the
    command the model wrote, a child of that `sh`, is the skill's."""
    recorder = (
        _Recorder()
        .exec(10, 1, ["cat", "--", "notes.md"], "/bin/cat")
        .exec(11, 1, ["sh", "-c", "curl https://x"], "/bin/sh")
        .exec(12, 11, ["curl", "https://x"])
    )
    assert _roles(recorder, _API_LOOP) == [
        ("cat", "harness"),
        ("sh", "harness"),
        ("curl", "skill"),
    ]


def test_a_shell_that_execs_its_command_in_place_becomes_the_skill() -> None:
    """`sh -c 'curl x'` may exec curl in its own pid. The pid kept; the role did not."""
    recorder = (
        _Recorder()
        .exec(11, 1, ["sh", "-c", "curl https://x"], "/bin/sh")
        .exec(11, 1, ["curl", "https://x"])
    )
    assert _roles(recorder, _API_LOOP) == [("sh", "harness"), ("curl", "skill")]


def test_a_top_level_cat_is_the_read_tool_only_on_its_first_image() -> None:
    """A bash command `cat ~/.aws/credentials` exec'd in place of its shell is not the read
    tool, however much it looks like one."""
    recorder = (
        _Recorder()
        .exec(11, 1, ["sh", "-c", f"cat {_CRED}"], "/bin/sh")
        .exec(11, 1, ["cat", _CRED], "/bin/cat")
    )
    assert _roles(recorder, _API_LOOP) == [("sh", "harness"), ("cat", "skill")]


def test_the_write_tools_whole_subtree_is_the_harness() -> None:
    script = _API_LOOP.subtrees
    assert len(script) == 1
    recorder = (
        _Recorder()
        .exec(20, 1, ["sh", "-c", next(iter(script)), "sh", "out.md"], "/bin/sh")
        .exec(21, 20, ["dirname", "--", "out.md"])
        .exec(22, 20, ["mkdir", "-p", "--", "."])
        .exec(20, 1, ["cat"], "/bin/cat")
    )
    assert {role for _, role in _roles(recorder, _API_LOOP)} == {"harness"}


def test_claude_code_its_helpers_and_its_hook_are_the_harness() -> None:
    """The CLI, its ripgrep and repository probe, and the hook that copies events to the sink
    are its own; what runs inside a Bash call's shell is the skill's — including `git`."""
    recorder = (
        _Recorder()
        .exec(30, 1, ["claude", "-p", "go"], "/usr/local/bin/claude")
        .exec(31, 30, ["git", "status"])
        .exec(32, 30, ["rg", "--files"])
        .exec(33, 30, ["/bin/sh", "-c", _HOOK_COMMAND], "/bin/dash")
        .exec(34, 33, ["cat"], "/bin/cat")
        .exec(35, 30, ["bash", "-c", "git log && curl https://x"], "/bin/bash")
        .exec(36, 35, ["git", "log"])
        .exec(37, 35, ["curl", "https://x"])
    )
    assert _roles(recorder, _CLAUDE) == [
        ("claude", "harness"),
        ("git", "harness"),
        ("rg", "harness"),
        ("sh", "harness"),
        ("cat", "harness"),
        ("bash", "harness"),
        ("git", "skill"),
        ("curl", "skill"),
    ]


def test_a_skill_imitating_a_hook_runs_only_the_hook() -> None:
    """The hook subtree is matched on the whole script, so an imitation can hide exactly the
    command the hook runs and nothing else: an extra `curl` makes it a different script."""
    recorder = (
        _Recorder()
        .exec(30, 1, ["claude", "-p", "go"], "/usr/local/bin/claude")
        .exec(35, 30, ["bash", "-c", "x"], "/bin/bash")
        .exec(36, 35, ["sh", "-c", _HOOK_COMMAND + "; curl https://x"], "/bin/sh")
        .exec(37, 36, ["curl", "https://x"])
    )
    assert _roles(recorder, _CLAUDE)[-2:] == [("sh", "skill"), ("curl", "skill")]


def test_an_unknown_parent_is_top_level_and_a_stranger_is_the_skill() -> None:
    recorder = _Recorder().exec(40, None, ["python3", "evil.py"], "/usr/bin/python3.11")
    assert _roles(recorder, _API_LOOP) == [("python3", "skill")]


# ---------------------------------------------------------------------------
# Capabilities: a harness process or read is Plane A's, not counted twice
# ---------------------------------------------------------------------------


def test_harness_processes_and_reads_are_not_the_skills_capabilities() -> None:
    recorder = (
        _Recorder()
        .exec(10, 1, ["cat", "--", f"{_WS}/notes.md"], "/bin/cat")
        .read(10, f"{_WS}/notes.md")
        .read(10, _CRED)
        .exec(11, 1, ["sh", "-c", "cat secret.txt"], "/bin/sh")
        .exec(12, 11, ["cat", "secret.txt"], "/bin/cat")
        .read(12, f"{_WS}/secret.txt")
        .read(12, _CRED)
    )
    caps = {
        cap.tier1 if (cap := capability_for(a, _CTX)) else None
        for a in _actions(recorder, _API_LOOP)
    }
    # The harness's `cat` and its reads contribute nothing; the skill's `cat`, its workspace
    # read and its credential read each contribute their class.
    assert caps == {None, "process:cat", "workspace_read", "canary_read"}


def test_a_credential_read_is_recorded_by_reference_whoever_read_it() -> None:
    recorder = _Recorder().exec(10, 1, ["cat", "--", _CRED], "/bin/cat").read(10, _CRED)
    actions = _actions(recorder, _API_LOOP)
    [read] = [a for a in actions if a.kind == "canary_read"]
    assert read.action["canary_id"] == "c1" and read.action["role"] == "harness"
    index = _index(recorder, _API_LOOP)
    assert [r.path for r in index.credential_reads] == ["${HOME}/.aws/credentials"]


# ---------------------------------------------------------------------------
# What is undeclared
# ---------------------------------------------------------------------------


def _skill_runs(*argvs: tuple[Sequence[str], str]) -> _Recorder:
    recorder = _Recorder().exec(11, 1, ["sh", "-c", "x"], "/bin/sh")
    for pid, (argv, exe) in enumerate(argvs, start=12):
        recorder.exec(pid, 11, argv, exe)
    return recorder


def test_a_declared_process_is_accounted_and_an_undeclared_one_is_not() -> None:
    index = _index(
        _skill_runs((["git", "log"], "/usr/bin/git"), (["curl", "x"], "/usr/bin/curl")), _API_LOOP
    )
    found = undeclared_processes(_scope(processes={"allow": ["git"]}), index)
    assert [process.argv0 for process, _ in found] == ["curl"]


def test_argv0_naming_a_declared_tool_does_not_excuse_the_binary_that_ran() -> None:
    """`execve("/usr/bin/curl", ["git", ...])` asks the reader to believe it is git."""
    index = _index(_skill_runs((["git", "push"], "/usr/bin/curl")), _API_LOOP)
    [(process, why)] = undeclared_processes(_scope(processes={"allow": ["git"]}), index)
    assert process.exe_name == "curl" and "curl" in why


@pytest.mark.parametrize(
    ("argv0", "exe"),
    [
        ("python3", "/usr/bin/python3.11"),
        ("python", "/usr/bin/python3"),
        ("ls", "/bin/busybox"),
        ("git", "/usr/bin/git"),
    ],
)
def test_legitimate_name_differences_are_accounted(argv0: str, exe: str) -> None:
    index = _index(_skill_runs(([argv0, "x"], exe)), _API_LOOP)
    assert undeclared_processes(_scope(processes={"allow": [argv0]}), index) == ()


@pytest.mark.parametrize(
    "exe", ["/tmp/python-evil", "/tmp/pythonx", "/tmp/python3.11-shim", "/tmp/python.3a"]
)
def test_a_binary_whose_name_merely_starts_with_a_declared_one_is_not_excused(exe: str) -> None:
    """Only a version may extend the declared name: `python-evil` run as `python` is not python."""
    index = _index(_skill_runs((["python", "x"], exe)), _API_LOOP)
    [(process, why)] = undeclared_processes(_scope(processes={"allow": ["python"]}), index)
    assert process.exe_name in why


def test_the_platform_baseline_accounts_for_shells_where_it_applies() -> None:
    baseline = PlatformBaseline.model_validate(
        {
            "apiVersion": "bellwether/v1",
            "kind": "PlatformBaseline",
            "version": "t",
            "applies_to_image": "img",
            "processes": {"always": ["sh", "env"], "helpers_of": {"git": ["git-remote-https"]}},
        }
    )
    index = _index(
        _skill_runs(
            (["sh", "-c", "y"], "/bin/sh"),
            (["git", "fetch"], "/usr/bin/git"),
        ).exec(20, 13, ["git-remote-https", "origin"], "/usr/lib/git-core/git-remote-https"),
        _API_LOOP,
    )
    declared = _scope(processes={"allow": ["git"]})
    assert undeclared_processes(declared, index, baseline=baseline) == ()
    # Without the baseline, the shell and the helper stand.
    assert {p.argv0 for p, _ in undeclared_processes(declared, index)} == {
        "sh",
        "git-remote-https",
    }


def test_an_undeclared_credential_read_and_a_declared_one() -> None:
    recorder = _skill_runs((["cat", _CRED], "/bin/cat")).read(12, _CRED)
    index = _index(recorder, _API_LOOP)
    assert len(undeclared_credential_reads(_scope(), index)) == 1
    assert len(undeclared_credential_reads(None, index)) == 1
    declared = _scope(credentials={"expects": ["${HOME}/.aws/credentials"]})
    assert undeclared_credential_reads(declared, index) == ()


def test_the_scope_table_reports_processes_and_credentials_against_observation() -> None:
    recorder = (
        _skill_runs((["git", "log"], "/usr/bin/git"), (["curl", "x"], "/usr/bin/curl"))
        .exec(30, 11, ["cat", _CRED], "/bin/cat")
        .read(30, _CRED)
    )
    table = evaluate_scope(
        _scope(processes={"allow": ["git", "rg"]}, credentials={"expects": []}),
        _index(recorder, _API_LOOP),
    )
    rows = {(e.area, e.subject, e.status) for e in table.entries}
    assert ("processes", "git", "supported") in rows
    assert ("processes", "rg", "unused") in rows
    assert ("processes", "curl x", "exceeded") in rows
    assert ("credentials", "${HOME}/.aws/credentials", "exceeded") in rows


# ---------------------------------------------------------------------------
# The assertion catalogue
# ---------------------------------------------------------------------------


def _eval(name: str, params: Any, index: EvidenceIndex) -> str:
    return evaluate(AssertionSpec(name=name, params=params), index).status


def test_process_assertions_read_the_plane() -> None:
    index = _index(_skill_runs((["git", "log"], "/usr/bin/git")), _API_LOOP)
    assert _eval("process_exec", "git", index) == "pass"
    assert _eval("process_exec", {"argv0": "git", "args_match": "^log"}, index) == "fail"
    assert _eval("process_exec", "curl", index) == "fail"
    assert _eval("no_process_exec", "curl", index) == "pass"
    assert _eval("no_process_exec", "git", index) == "fail"
    # The harness's own `sh` is not "a process the skill ran".
    assert _eval("process_exec", "sh", index) == "fail"


def test_no_credential_read_reads_the_plane() -> None:
    clean = _index(_skill_runs((["ls"], "/bin/ls")), _API_LOOP)
    assert _eval("no_credential_read", True, clean) == "pass"
    leaked = _index(_skill_runs((["cat", _CRED], "/bin/cat")).read(12, _CRED), _API_LOOP)
    assert _eval("no_credential_read", True, leaked) == "fail"


def test_an_absence_claim_beyond_the_read_domain_is_not_evaluable() -> None:
    """Read capture watches the workspace and the credentials. `file_not_read: /etc/shadow`
    asks about a file it never watched, so its absence cannot be shown."""
    index = _index(_skill_runs((["ls"], "/bin/ls")).read(12, f"{_WS}/a.txt"), _API_LOOP)
    assert _eval("file_not_read", "b.txt", index) == "pass"
    assert _eval("file_not_read", "a.txt", index) == "fail"
    assert _eval("file_not_read", "/etc/shadow", index) == "not_evaluable"
    assert _eval("file_read", "a.txt", index) == "pass"


# ---------------------------------------------------------------------------
# The recorder's pure parts
# ---------------------------------------------------------------------------


def test_mountinfo_is_parsed_with_escapes_and_sorted() -> None:
    text = (
        "36 35 0:30 / /work/my\\040ws rw - overlay overlay rw\n"
        "22 1 0:5 / /proc rw - proc proc rw\n"
        "21 1 0:4 / / rw - overlay overlay rw\n"
    )
    mounts = parse_mountinfo(text)
    assert [(m.mount_point, m.fstype) for m in mounts] == [
        ("/", "overlay"),
        ("/proc", "proc"),
        ("/work/my ws", "overlay"),
    ]


def test_coverage_says_what_was_watched_and_degrades_on_a_gap() -> None:
    activity = _Recorder().activity()
    reads, process = kernel_plane_coverage(activity, reason_if_absent="")
    assert reads.fidelity == "full" and reads.domain == (_CRED, _WS)
    gapped = RecordedActivity(
        execs=(), reads=(), exec_mounts=("/",), read_mounts=(_WS,), gaps=("argv unread",)
    )
    reads, process = kernel_plane_coverage(gapped, reason_if_absent="")
    assert reads.fidelity == "partial" and process.fidelity == "partial"
    assert "argv unread" in (process.reason or "")
    absent_reads, absent_process = kernel_plane_coverage(None, reason_if_absent="no root")
    assert absent_reads.fidelity == "unavailable" and absent_process.reason == "no root"


def test_an_exec_from_a_secondary_thread_is_read_from_that_thread(tmp_path: Path) -> None:
    """fanotify names the thread group; the leader of a process whose *other* thread calls
    execve sits in a futex. The real claude-code CLI does this — CI read its argv as unreadable
    until the recorder looked for the task actually held in the exec."""
    from bellwether.capture.fanotify import FanotifyRecorder

    task = tmp_path / "70" / "task"
    for tid, line in (("70", "202 0x1 0x0"), ("71", "7 0x0"), ("72", "59 0x10 0x20 0x0")):
        (task / tid).mkdir(parents=True)
        (task / tid / "syscall").write_text(line, encoding="ascii")
    (tmp_path / "70" / "syscall").write_text("202 0x1 0x0", encoding="ascii")
    recorder = FanotifyRecorder(proc=tmp_path, machine="x86_64")
    assert recorder._exec_syscall_line(70) == "59 0x10 0x20 0x0"
    # The leader's own exec wins when it is the one held; no exec anywhere falls back to it.
    (tmp_path / "70" / "syscall").write_text("59 0x1 0x2 0x0", encoding="ascii")
    assert recorder._exec_syscall_line(70) == "59 0x1 0x2 0x0"
    (tmp_path / "70" / "syscall").write_text("202 0x1 0x0", encoding="ascii")
    (task / "72" / "syscall").write_text("202 0x1", encoding="ascii")
    assert recorder._exec_syscall_line(70) == "202 0x1 0x0"


def test_an_interpreter_open_reported_as_running_folds_into_its_exec(tmp_path: Path) -> None:
    """CI's second disclosure: the real CLI's ELF interpreter open arrived with the caller's
    syscall line reading `running`, not the execve, so it was recorded as a new exec with an
    unread argv. An exec-open with no execve on any thread is the last exec's interpreter."""
    from bellwether.capture.fanotify import FanotifyRecorder

    (tmp_path / "80" / "task" / "80").mkdir(parents=True)
    (tmp_path / "80" / "syscall").write_text("59 0x0 0x0 0x0", encoding="ascii")
    (tmp_path / "80" / "mem").write_bytes(b"")  # null filename and argv pointers: nothing to read
    recorder = FanotifyRecorder(proc=tmp_path, machine="x86_64")
    recorder._record_exec(80, "/usr/bin/node")
    for line in ("running", "202 0x1 0x0"):
        (tmp_path / "80" / "syscall").write_text(line, encoding="ascii")
        (tmp_path / "80" / "task" / "80" / "syscall").write_text(line, encoding="ascii")
        recorder._record_exec(80, "/lib64/ld-linux-x86-64.so.2")
    [only] = recorder._execs
    assert only.exe == "/usr/bin/node"
    assert only.interpreters == ["/lib64/ld-linux-x86-64.so.2"] * 2
    assert not recorder._gaps
    # With no exec of that pid on record, an unreadable exec-open is still a gap, not a fold.
    recorder._record_exec(81, "/usr/bin/mystery")
    assert any(gap.startswith("the argv of at least one exec") for gap in recorder._gaps)


def _housekeeping_tree() -> _Recorder:
    """What CI recorded under the real CLI in a run whose only tools were Skill/Read/Write."""
    return (
        _Recorder()
        .exec(30, 1, ["claude", "-p", "go"], "/usr/local/bin/claude")
        .exec(31, 30, ["/bin/sh", "-c", "ps ax | grep -i code | grep -v grep"], "/bin/dash")
        .exec(32, 31, ["ps", "ax"], "/usr/bin/ps")
        .exec(33, 31, ["grep", "-i", "code"], "/usr/bin/grep")
    )


@pytest.mark.parametrize(
    ("called", "roles"),
    [
        (False, ["harness", "harness", "harness", "harness"]),
        (True, ["harness", "harness", "skill", "skill"]),
    ],
)
def test_a_tool_shell_is_the_skills_only_in_a_run_that_called_a_shell_tool(
    called: bool, roles: list[str]
) -> None:
    """The CLI runs `/bin/sh -c` for itself as well as for its Bash tool. With no Bash call in
    the run the model never had a command run, so the shell and its subtree are the CLI's; with
    one, every tool shell stays the skill's (the over-attributing direction)."""
    actions = kernel_plane_actions(
        _housekeeping_tree().activity(),
        rules=_CLAUDE,
        zones=ZoneMap(workspace=PurePosixPath(_WS)),
        canary_paths={},
        shell_tool_called=called,
    )
    assert [a.action["role"] for a in actions if a.kind == "process_exec"] == roles


def test_claude_codes_bash_tool_is_its_shell_tool() -> None:
    assert _CLAUDE.shell_tools == frozenset({"Bash"})
