"""Parser tests against real BSI WID documents (data/samples/bsi_csaf/)."""

from datetime import datetime, timezone

from conftest import sample

from radar.sources.bsi_csaf import ALLOWED_TLP, parse_document, parse_feed


def doc(name: str):
    return parse_document(sample(f"bsi_csaf/{name}.json"))


def test_feed_entries_have_id_url_and_dates():
    entries = parse_feed(sample("bsi_csaf/feed-bsi-wid-white.excerpt.json"))
    assert len(entries) == 25
    first = entries[0]
    assert first.advisory_id == "WID-SEC-W-2026-3674"
    assert first.url.endswith("/white/2026/wid-sec-w-2026-3674.json")
    assert first.updated == datetime(2026, 9, 29, 22, 0, tzinfo=timezone.utc)


def test_feed_updated_equals_document_release_date():
    # Ingestion relies on this to skip documents it already has.
    entries = parse_feed(sample("bsi_csaf/feed-bsi-wid-white.excerpt.json"))
    assert entries[0].updated == doc("wid-sec-w-2026-3674").current_release_date


def test_document_header_fortios():
    advisory = doc("wid-sec-w-2026-0085")
    assert advisory.advisory_id == "WID-SEC-W-2026-0085"
    assert advisory.version == 2
    assert advisory.title == "Fortinet FortiOS: Schwachstelle ermöglicht Codeausführung"
    assert advisory.severity_text == "hoch"
    assert advisory.tlp in ALLOWED_TLP
    assert advisory.revision_summary == "Exploit aufgenommen"
    assert advisory.attack_summary.startswith("Ein entfernter, anonymer Angreifer")
    assert advisory.source_url.endswith("wid-sec-w-2026-0085.json")
    assert advisory.portal_url == (
        "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0085"
    )
    assert advisory.cves == {"CVE-2025-25249"}


def test_version_ranges_and_fixed_nodes_fortios():
    advisory = doc("wid-sec-w-2026-0085")
    ranges = [p for p in advisory.products if p.node_category == "product_version_range"]
    fixed = [p for p in advisory.products if p.is_fixed_node]

    # One range per release line, kept as BSI's free text.
    assert sorted(p.version_text for p in ranges) == [
        "<6.4.17", "<7.0.18", "<7.2.12", "<7.4.9", "<7.6.4",
    ]
    assert all(p.vendor == "Fortinet" and p.product_name == "FortiOS" for p in ranges)
    assert all(p.cpe is None for p in ranges)  # ranges carry no CPE

    assert sorted(p.version_text for p in fixed) == ["6.4.17", "7.0.18", "7.2.12", "7.4.9", "7.6.4"]
    assert all(p.cpe.startswith("cpe:/o:fortinet:fortios:") for p in fixed)

    # Fixed nodes are never referenced by product_status (D-006).
    affected = set(advisory.vulnerabilities[0].known_affected)
    assert affected == {p.product_id for p in ranges}


def test_version_inside_product_name_exchange():
    advisory = doc("wid-sec-w-2026-3268")
    assert {(p.vendor, p.product_name, p.version_text) for p in advisory.products} == {
        ("Microsoft", "Exchange", "Server 2016 Cumulative Update 23"),
        ("Microsoft", "Exchange", "Server 2019 Cumulative Update 14"),
        ("Microsoft", "Exchange", "Server Subscription Edition RTM"),
    }
    assert len(advisory.cves) == 9


def test_printer_models_without_firmware_version_kyocera():
    advisory = doc("wid-sec-w-2026-2273")
    assert len(advisory.products) == 15
    assert all(p.vendor == "Kyocera" and p.product_name == "Printer" for p in advisory.products)
    assert "Command Center RX TASKalfa 2552ci" in {p.version_text for p in advisory.products}


def test_many_vendors_in_one_advisory_openssl():
    advisory = doc("wid-sec-w-2026-0234")
    assert advisory.version == 60
    assert len(advisory.products) == 117
    assert len({p.vendor for p in advisory.products}) > 10
    # Products without any version node have an empty version text.
    debian = next(p for p in advisory.products if p.full_name == "Debian Linux")
    assert (debian.node_category, debian.version_text) == ("product_name", "")


def test_nested_product_name_keeps_outer_product_redhat():
    advisory = doc("wid-sec-w-2026-3605")
    # Real shape: Red Hat > "Enterprise Linux" > { product_name (no version), "9", ... }
    rhel = [p for p in advisory.products if p.vendor == "Red Hat"]
    assert {p.product_name for p in rhel} == {"Enterprise Linux"}
    assert {p.version_text for p in rhel} == {
        "", "9", "Advanced Cluster Management for Kubernetes",
    }
    unversioned = next(p for p in rhel if p.version_text == "")
    assert unversioned.full_name == "Red Hat Enterprise Linux"


def test_last_affected_status_poppler():
    advisory = doc("wid-sec-w-2026-3674")
    assert all(v.last_affected and not v.known_affected for v in advisory.vulnerabilities)
    assert {p.version_text for p in advisory.products} == {"<=26.08.0"}


def test_vulnerability_without_cve_moodle():
    advisory = doc("wid-sec-w-2026-3671")
    assert len(advisory.vulnerabilities) == 1
    assert advisory.vulnerabilities[0].cve is None
    assert advisory.cves == set()
    assert len(advisory.vulnerabilities[0].known_affected) == 4
