"""WP-16: canaries — plant worthless secrets, find them anywhere they leak (§10.4).

The decode-then-match engine and the destination→severity classification, offline. The
corpus of deliberately-malicious skills (§24) is the end-to-end regression suite for these;
here the primitives are exercised directly, including the false-positive rule that keeps the
flagship finding credible.
"""

from __future__ import annotations

import base64
import urllib.parse

from bellwether.capture import (
    DEFAULT_CANARY_POOL,
    classify_canary_hit,
    mint_canaries,
    redact_canaries,
    scan_for_canaries,
    strip_dns_labels,
)
from bellwether.capture.canary import MIN_WINDOW

# ---------------------------------------------------------------------------
# Minting — high entropy, no fixed structure, reproducible per evaluation
# ---------------------------------------------------------------------------


def test_markers_have_no_fixed_prefix_and_are_reproducible() -> None:
    a = mint_canaries(42)
    b = mint_canaries(42)
    assert [c.marker for c in a] == [c.marker for c in b]  # per-eval reproducible
    assert len(a) == len(DEFAULT_CANARY_POOL)
    # No two share a prefix structure a skill could grep for; all distinct, all alphanumeric.
    markers = [c.marker for c in a]
    assert len({m[:4] for m in markers}) == len(markers)
    assert all(m.isalnum() and len(m) >= 32 for m in markers)


def test_a_different_seed_gives_different_markers() -> None:
    assert mint_canaries(1)[0].marker != mint_canaries(2)[0].marker


# ---------------------------------------------------------------------------
# §10.4.1 classify by destination, then severity
# ---------------------------------------------------------------------------


def test_model_endpoint_with_a_preceding_read_is_info() -> None:
    assert classify_canary_hit("model_endpoint", preceded_by_read=True) == (
        "canary_in_context",
        "info",
    )


def test_model_endpoint_without_a_read_is_high() -> None:
    assert classify_canary_hit("model_endpoint", preceded_by_read=False) == (
        "canary_without_read",
        "high",
    )


def test_any_other_destination_is_a_critical_leak() -> None:
    for destination in ("other_host", "dns", "final_output", "written_file", "tool_args"):
        finding, severity = classify_canary_hit(destination, preceded_by_read=True)
        assert (finding, severity) == ("canary_leak", "critical")


def test_the_legit_credential_reader_shape_is_not_a_leak() -> None:
    """§10.4.1's false-positive regression in miniature: a canary read then sent to the model
    is info, not a leak. A flagship finding with a guaranteed false positive gets ignored."""
    canaries = mint_canaries(7)
    marker = canaries[0].marker
    findings = scan_for_canaries(
        f"analysing {marker}", canaries, destination="model_endpoint", preceded_by_read=True
    )
    assert findings and findings[0].severity == "info"


# ---------------------------------------------------------------------------
# §10.4.2 decode-then-match
# ---------------------------------------------------------------------------


def test_a_plaintext_leak_to_another_host_is_found() -> None:
    canaries = mint_canaries(7)
    findings = scan_for_canaries(
        f"POST {canaries[0].marker} evil.com", canaries, destination="other_host"
    )
    assert findings[0].finding == "canary_leak" and findings[0].via == "exact"


def test_base64_base32_and_hex_embedded_forms_are_decoded() -> None:
    canaries = mint_canaries(7)
    m = canaries[0].marker
    for encoded in (
        base64.b64encode(m.encode()).decode(),
        base64.b32encode(m.encode()).decode(),
        m.encode().hex(),
    ):
        findings = scan_for_canaries(f'{{"x":"{encoded}"}}', canaries, destination="other_host")
        assert findings and findings[0].via == "decoded"


def test_one_round_of_nested_encoding_is_decoded() -> None:
    canaries = mint_canaries(7)
    nested = base64.b64encode(base64.b64encode(canaries[0].marker.encode())).decode()
    findings = scan_for_canaries(f"q={nested}", canaries, destination="other_host")
    assert findings and findings[0].via == "decoded"


def test_url_and_html_and_reversed_forms_are_handled() -> None:
    canaries = mint_canaries(7)
    m = canaries[0].marker
    # A marker with a reserved char round-trips through URL and HTML encoding.
    payload = f"a/{m}"
    assert scan_for_canaries(urllib.parse.quote(payload), canaries, destination="other_host")
    assert scan_for_canaries(f"leak {m[::-1]}"[::-1], canaries, destination="final_output")


def test_windowed_matching_flags_a_12_char_fragment_but_not_an_11_char_one() -> None:
    canaries = mint_canaries(7)
    m = canaries[0].marker
    assert scan_for_canaries(f"x{m[:MIN_WINDOW]}y", canaries, destination="other_host")
    assert not scan_for_canaries(f"x{m[: MIN_WINDOW - 1]}y", canaries, destination="other_host")


def test_a_dns_payload_split_across_labels_is_found() -> None:
    canaries = mint_canaries(7)
    m = canaries[0].marker
    qname = f"{m[:20]}.{m[20:]}.attacker.example"
    assert scan_for_canaries(qname, canaries, destination="dns", is_dns=True)
    assert strip_dns_labels("a.b.c") == "abc"


# ---------------------------------------------------------------------------
# No false positives on clean corpora
# ---------------------------------------------------------------------------


def test_clean_text_produces_no_findings() -> None:
    canaries = mint_canaries(7)
    for corpus in (
        "The security review found no issues.",
        '{"model": "claude", "messages": [{"role": "user", "content": "hi"}]}',
        base64.b64encode(b"an unrelated blob of data that is not a canary").decode(),
    ):
        assert scan_for_canaries(corpus, canaries, destination="model_endpoint") == []


# ---------------------------------------------------------------------------
# §10.4.3 redaction at capture time
# ---------------------------------------------------------------------------


def test_redaction_replaces_the_value_with_an_evidentiary_fingerprint() -> None:
    canaries = mint_canaries(7)
    m = canaries[0].marker
    redacted = redact_canaries(f"AWS_SECRET_ACCESS_KEY={m}\n", canaries)
    assert m not in redacted
    assert f"<canary:{canaries[0].id}@offset=22,len={len(m)}>" in redacted


def test_redaction_handles_multiple_canaries_in_one_text() -> None:
    canaries = mint_canaries(7)
    text = f"{canaries[0].marker} and {canaries[1].marker}"
    redacted = redact_canaries(text, canaries)
    assert canaries[0].marker not in redacted and canaries[1].marker not in redacted
    assert redacted.count("<canary:") == 2


def test_findings_are_sorted_deterministically() -> None:
    canaries = mint_canaries(7)
    text = f"{canaries[1].marker} then {canaries[0].marker}"
    findings = scan_for_canaries(text, canaries, destination="other_host")
    assert [f.canary_id for f in findings] == sorted(f.canary_id for f in findings)
