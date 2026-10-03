"""Ingestion: pull advisories and enrichment data and store them idempotently.

Running this twice with the same input changes nothing the second time. That
matters because WF1 runs it every morning and may be re-run by hand at any time.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from radar.sources import bsi_csaf, epss, euvd, kev
from radar.sources.fetcher import FetchError, Fetcher

log = logging.getLogger(__name__)


@dataclass
class IngestStats:
    feed_entries: int = 0
    new_advisories: int = 0
    updated_advisories: int = 0
    unchanged_advisories: int = 0
    skipped_tlp: int = 0
    failed_documents: int = 0
    cves_in_window: int = 0
    kev_catalog_size: int = 0
    kev_cves_in_window: int = 0
    advisories_with_kev: int = 0
    epss_scores: int = 0
    cvss_looked_up: int = 0
    cvss_found: int = 0
    http_requests: int = 0
    problems: list[str] = field(default_factory=list)


def run_ingest(
    conn: psycopg.Connection, snapshot_dir: Path, cache_dir: Path, days: int, offline: bool
) -> IngestStats:
    stats = IngestStats()
    fetcher = Fetcher(snapshot_dir, offline=offline)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    run_id = conn.execute(
        "INSERT INTO radar.ingest_runs (mode, snapshot) VALUES (%s, %s) RETURNING run_id",
        ("offline" if offline else "live", str(snapshot_dir)),
    ).fetchone()[0]
    conn.commit()

    try:
        window_ids = _ingest_advisories(conn, fetcher, cache_dir, since, stats)
        _ingest_kev(conn, fetcher, stats)
        window_cves = _cves_of(conn, window_ids)
        stats.cves_in_window = len(window_cves)
        _ingest_epss(conn, fetcher, window_cves, stats)
        _count_kev_hits(conn, window_ids, stats)
        _ingest_cvss_for_kev_hits(conn, fetcher, window_ids, stats)
    finally:
        stats.http_requests = fetcher.requests_made
        fetcher.close()
        conn.execute(
            "UPDATE radar.ingest_runs SET finished_at = now(), stats = %s WHERE run_id = %s",
            (Jsonb(stats.__dict__), run_id),
        )
        conn.commit()
    return stats


# --- advisories -------------------------------------------------------------


def _ingest_advisories(conn, fetcher: Fetcher, cache_dir: Path, since, stats) -> list[str]:
    """Stores new revisions. Returns the ids of all advisories in the time window."""
    # In offline mode the snapshot's feed already is the window that was recorded.
    entries = bsi_csaf.load_feed(fetcher, cache_dir, since)
    stats.feed_entries = len(entries)

    # What we already have: advisory id -> release date of our latest revision.
    known = dict(
        conn.execute(
            "SELECT advisory_id, current_release_date FROM radar.advisories WHERE is_latest"
        ).fetchall()
    )

    for entry in entries:
        # The feed's `updated` equals the document's current_release_date, so an
        # advisory we already hold in that state needs no download at all.
        if entry.advisory_id in known and known[entry.advisory_id] >= entry.updated:
            stats.unchanged_advisories += 1
            continue
        try:
            doc = bsi_csaf.load_document(fetcher, entry)
        except (FetchError, json.JSONDecodeError) as error:
            # One broken document must not stop the whole run.
            stats.failed_documents += 1
            stats.problems.append(f"{entry.advisory_id}: {error}")
            continue
        if doc is None:
            stats.failed_documents += 1
            stats.problems.append(f"{entry.advisory_id}: document not available")
            continue

        advisory = bsi_csaf.parse_document(doc)
        if advisory.tlp not in bsi_csaf.ALLOWED_TLP:
            stats.skipped_tlp += 1
            continue

        outcome = store_advisory(conn, advisory, doc)
        conn.commit()
        if outcome == "new":
            stats.new_advisories += 1
        elif outcome == "updated":
            stats.updated_advisories += 1
        else:
            stats.unchanged_advisories += 1
    return [entry.advisory_id for entry in entries]


def store_advisory(conn, advisory: bsi_csaf.Advisory, raw: dict) -> str:
    """Stores one revision. Returns 'new', 'updated' or 'unchanged'."""
    row = conn.execute(
        "SELECT max(version) FROM radar.advisories WHERE advisory_id = %s",
        (advisory.advisory_id,),
    ).fetchone()
    latest_stored = row[0]
    if latest_stored is not None and latest_stored >= advisory.version:
        return "unchanged"

    with conn.transaction():
        conn.execute(
            "UPDATE radar.advisories SET is_latest = false WHERE advisory_id = %s AND is_latest",
            (advisory.advisory_id,),
        )
        conn.execute(
            """
            INSERT INTO radar.advisories (
                advisory_id, version, is_latest, title, severity_text, tlp,
                initial_release_date, current_release_date, revision_summary,
                attack_summary, product_description, source_url, portal_url,
                "references", raw)
            VALUES (%s, %s, true, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                advisory.advisory_id, advisory.version, advisory.title,
                advisory.severity_text, advisory.tlp, advisory.initial_release_date,
                advisory.current_release_date, advisory.revision_summary,
                advisory.attack_summary, advisory.product_description,
                advisory.source_url, advisory.portal_url,
                Jsonb(advisory.references), Jsonb(raw),
            ),
        )
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO radar.advisory_products (
                    advisory_id, version, product_id, vendor, product_name,
                    node_category, version_text, full_name, cpe, is_fixed_node)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                [
                    (
                        advisory.advisory_id, advisory.version, p.product_id, p.vendor,
                        p.product_name, p.node_category, p.version_text, p.full_name,
                        p.cpe, p.is_fixed_node,
                    )
                    for p in advisory.products
                ],
            )
            cur.executemany(
                """
                INSERT INTO radar.advisory_vulnerabilities (
                    advisory_id, version, position, cve, known_affected, last_affected)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                [
                    (
                        advisory.advisory_id, advisory.version, position, v.cve,
                        v.known_affected, v.last_affected,
                    )
                    for position, v in enumerate(advisory.vulnerabilities)
                ],
            )
    return "new" if latest_stored is None else "updated"


# --- enrichment -------------------------------------------------------------


def _ingest_kev(conn, fetcher: Fetcher, stats) -> None:
    try:
        loaded = kev.load_kev(fetcher)
    except FetchError as error:
        # Keep yesterday's catalog rather than failing the run.
        stats.problems.append(f"KEV: {error}")
        loaded = None
    if loaded:
        catalog_version, entries = loaded
        # The catalog is small and complete, so it is replaced as a whole.
        with conn.transaction():
            conn.execute("DELETE FROM radar.kev")
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO radar.kev (cve, vendor_project, product, vulnerability_name,
                                           date_added, due_date, ransomware_use, catalog_version)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve) DO NOTHING
                    """,
                    [
                        (
                            e.cve, e.vendor_project, e.product, e.vulnerability_name,
                            e.date_added, e.due_date, e.ransomware_use, catalog_version,
                        )
                        for e in entries
                    ],
                )
        conn.commit()
    stats.kev_catalog_size = conn.execute("SELECT count(*) FROM radar.kev").fetchone()[0]


def _cves_of(conn, advisory_ids: list[str]) -> list[str]:
    rows = conn.execute(
        """
        SELECT DISTINCT v.cve
        FROM radar.advisory_vulnerabilities v
        JOIN radar.advisories a USING (advisory_id, version)
        WHERE a.is_latest AND v.cve IS NOT NULL AND a.advisory_id = ANY(%s)
        """,
        (advisory_ids,),
    ).fetchall()
    return [row[0] for row in rows]


def _ingest_epss(conn, fetcher: Fetcher, cves: list[str], stats) -> None:
    try:
        scores = epss.load_epss(fetcher, cves)
    except FetchError as error:
        stats.problems.append(f"EPSS: {error}")
        return
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO radar.epss (cve, score, percentile, score_date)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (cve) DO UPDATE
               SET score = EXCLUDED.score, percentile = EXCLUDED.percentile,
                   score_date = EXCLUDED.score_date, fetched_at = now()
            """,
            [(s.cve, s.score, s.percentile, s.score_date) for s in scores],
        )
    conn.commit()
    stats.epss_scores = len(scores)


def _count_kev_hits(conn, advisory_ids: list[str], stats) -> None:
    row = conn.execute(
        """
        SELECT count(DISTINCT v.cve), count(DISTINCT a.advisory_id)
        FROM radar.advisory_vulnerabilities v
        JOIN radar.advisories a USING (advisory_id, version)
        JOIN radar.kev k ON k.cve = v.cve
        WHERE a.is_latest AND a.advisory_id = ANY(%s)
        """,
        (advisory_ids,),
    ).fetchone()
    stats.kev_cves_in_window, stats.advisories_with_kev = row


def _ingest_cvss_for_kev_hits(conn, fetcher: Fetcher, advisory_ids: list[str], stats) -> None:
    """CVSS for the KEV-listed CVEs of this window.

    EUVD answers one CVE per request and the window can hold tens of thousands
    of CVEs, so CVSS is fetched only where it is needed (D-019). In phase 1 that
    is the KEV hits; from phase 2 on, matching asks for the CVEs of advisories
    that actually touch a customer.
    """
    rows = conn.execute(
        """
        SELECT DISTINCT v.cve
        FROM radar.advisory_vulnerabilities v
        JOIN radar.advisories a USING (advisory_id, version)
        JOIN radar.kev k ON k.cve = v.cve
        WHERE a.is_latest AND a.advisory_id = ANY(%s)
        """,
        (advisory_ids,),
    ).fetchall()
    ensure_cvss(conn, fetcher, [row[0] for row in rows], stats)


def ensure_cvss(conn, fetcher: Fetcher, cves: list[str], stats) -> None:
    """Looks up CVSS for the CVEs we have no answer for yet and stores the result."""
    already = {
        row[0] for row in conn.execute("SELECT cve FROM radar.cvss WHERE cve = ANY(%s)", (cves,))
    }
    for cve in sorted(set(cves) - already):
        try:
            score = euvd.load_cvss(fetcher, cve)
        except FetchError as error:
            # EUVD is optional at runtime: scoring falls back to the BSI rating (D-002).
            stats.problems.append(f"EUVD {cve}: {error}")
            continue
        stats.cvss_looked_up += 1
        if score is None:
            if fetcher.offline:
                continue  # not in this snapshot; unknown, so store nothing
            score = euvd.CvssScore(cve, None, None, None, None)
        elif score.score is not None:
            stats.cvss_found += 1
        conn.execute(
            """
            INSERT INTO radar.cvss (cve, score, version, vector, source, source_id)
            VALUES (%s, %s, %s, %s, 'euvd', %s)
            ON CONFLICT (cve) DO NOTHING
            """,
            (score.cve, score.score, score.version, score.vector, score.source_id),
        )
        conn.commit()
