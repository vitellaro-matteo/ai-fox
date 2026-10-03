"""Parser tests for KEV, EPSS and EUVD."""

from datetime import date
from decimal import Decimal

import pytest
from conftest import FIXTURES, SAMPLES, load_json, sample

from radar.sources.epss import parse_epss
from radar.sources.euvd import parse_euvd_record
from radar.sources.kev import parse_kev

# --- CISA KEV (real sample) ---


def test_kev_entries():
    catalog_version, entries = parse_kev(sample("kev/kev.excerpt.json"))
    assert catalog_version == "2026.09.30"
    assert len(entries) == 30
    first = entries[0]
    assert first.cve == "CVE-2026-76504"
    assert first.vendor_project == "Cisco"
    assert first.date_added == date(2026, 9, 30)
    assert first.due_date == date(2026, 10, 3)


# --- FIRST EPSS (real sample) ---


def test_epss_strings_become_exact_decimals():
    scores = {s.cve: s for s in parse_epss(sample("epss/epss_batch.json"))}
    assert scores["CVE-2025-25249"].score == Decimal("0.038590000")
    assert scores["CVE-2025-25249"].score_date == date(2026, 9, 29)
    assert 0 <= scores["CVE-2024-21762"].percentile <= 1


def test_epss_omits_unknown_cves():
    # Five CVEs were requested; CVE-2099-0001 does not exist and is simply absent.
    scores = parse_epss(sample("epss/epss_batch.json"))
    assert len(scores) == 4
    assert "CVE-2099-0001" not in {s.cve for s in scores}


# --- ENISA EUVD ---
# EUVD data is not committed (D-008). The committed fixture is hand-written:
# real field names and formats, neutral values.


def test_euvd_score_with_version():
    record = load_json(FIXTURES / "euvd_record_synthetic.json")
    score = parse_euvd_record("CVE-2000-0001", record)
    assert score.score == Decimal("7.4")
    assert score.version == "3.1"
    assert score.vector.startswith("CVSS:3.1/")
    assert score.source_id == "EUVD-2000-0001"


def test_euvd_score_without_version_counts_as_missing():
    record = load_json(FIXTURES / "euvd_record_synthetic.json")
    del record["baseScoreVersion"]
    score = parse_euvd_record("CVE-2000-0001", record)
    assert (score.score, score.version, score.vector) == (None, None, None)


def test_euvd_epss_field_is_ignored():
    # EUVD's epss is in percent; FIRST is our only EPSS source (D-004).
    record = load_json(FIXTURES / "euvd_record_synthetic.json")
    assert not hasattr(parse_euvd_record("CVE-2000-0001", record), "epss")


REAL_EUVD_SAMPLE = SAMPLES / "euvd" / "enisaid_CVE-2025-25249.json"


@pytest.mark.skipif(not REAL_EUVD_SAMPLE.exists(), reason="real EUVD sample is local only (D-008)")
def test_euvd_real_sample():
    score = parse_euvd_record("CVE-2025-25249", load_json(REAL_EUVD_SAMPLE))
    assert score.score == Decimal("7.4")
    assert score.version == "3.1"
    assert score.source_id == "EUVD-2026-2223"
