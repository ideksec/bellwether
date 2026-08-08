"""BW-29: the supply-chain pin lint also covers container/service images and ``docker run``.

``tools/pin_lint.py`` already pinned ``uses:`` actions, ``*_IMAGE`` env vars, ``docker pull``,
and Dockerfile ``FROM``. A mutable image can also enter a workflow through a job/step
``container:`` (inline or its ``image:`` mapping), a ``services:`` entry's ``image:``, or a
``docker run`` in a step — those are covered here. The lint flags an unpinned *tagged* image in
each, while never mistaking a job whose id is ``container`` (a mapping key with no inline value)
or a ``-p host:port`` mapping for an image, and never flagging a ``${{ var }}`` reference.

``pin_lint`` lives in ``tools/`` outside the package; ``conftest.py`` puts that directory on
``sys.path`` (the same way ``test_language_lint.py`` imports its tool).
"""

from __future__ import annotations

from pathlib import Path

import pin_lint

REPO_ROOT = Path(__file__).resolve().parent.parent


def _check(tmp_path: Path, body: str) -> list[str]:
    workflow = tmp_path / "wf.yml"
    workflow.write_text(body, encoding="utf-8")
    return pin_lint.check_workflow(workflow)


def test_a_container_with_an_inline_tagged_image_is_flagged(tmp_path: Path) -> None:
    """The BW-29 anchor case: ``container: node:18`` is a mutable tag and must be flagged."""
    problems = _check(tmp_path, "jobs:\n  build:\n    container: node:18\n")
    assert len(problems) == 1
    assert "node:18" in problems[0]


def test_a_container_mapping_image_is_flagged(tmp_path: Path) -> None:
    problems = _check(tmp_path, "jobs:\n  build:\n    container:\n      image: node:18\n")
    assert len(problems) == 1
    assert "node:18" in problems[0]


def test_a_services_image_is_flagged(tmp_path: Path) -> None:
    body = "jobs:\n  build:\n    services:\n      db:\n        image: postgres:16\n"
    problems = _check(tmp_path, body)
    assert len(problems) == 1
    assert "postgres:16" in problems[0]


def test_a_docker_run_image_is_flagged_but_a_port_mapping_is_not(tmp_path: Path) -> None:
    """The image is resolved past the flags: ``-p 8080:80`` is a value-taking flag, so its
    ``host:port`` argument is neither scanned as nor mistaken for the image."""
    body = "jobs:\n  build:\n    steps:\n      - run: docker run --rm -p 8080:80 redis:7 serve\n"
    problems = _check(tmp_path, body)
    assert len(problems) == 1
    assert "redis:7" in problems[0]
    assert "8080" not in problems[0]


def test_a_digest_pinned_container_is_accepted(tmp_path: Path) -> None:
    body = "jobs:\n  build:\n    container: node:18@sha256:" + "a" * 64 + "\n"
    assert _check(tmp_path, body) == []


def test_a_job_named_container_is_not_mistaken_for_an_image(tmp_path: Path) -> None:
    """A job whose id is ``container`` is a mapping key with no inline value; it must not be
    read as ``container: <image>``. The project's own ci.yml relies on this."""
    body = "jobs:\n  container:\n    runs-on: ubuntu-latest\n"
    assert _check(tmp_path, body) == []


def test_a_var_image_is_not_flagged(tmp_path: Path) -> None:
    body = "jobs:\n  build:\n    container: ${{ matrix.image }}\n"
    assert _check(tmp_path, body) == []


def test_an_untagged_bare_image_is_left_alone(tmp_path: Path) -> None:
    """Only a value that carries a tag is flagged, so a non-image token can never trip the
    scan; a bare ``node`` (no tag) is out of scope here as the task specifies."""
    assert _check(tmp_path, "jobs:\n  build:\n    container: node\n") == []


def test_the_repo_workflows_still_pass(tmp_path: Path) -> None:
    """No false positive on the project's own workflows — in particular ci.yml's ``container:``
    *job* and the digest-pinned ``BELLWETHER_TEST_IMAGE``."""
    for name in ("bellwether.yml", "ci.yml"):
        assert pin_lint.check_workflow(REPO_ROOT / ".github" / "workflows" / name) == []
