"""Command line entry point, run inside the radar-api container.

    python -m radar.cli migrate
    python -m radar.cli ingest [--days N] [--offline SNAPSHOT_DIR]
"""

import argparse
import logging
import os
import sys
from datetime import date
from pathlib import Path

from radar import db
from radar.ingest import IngestStats, run_ingest

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))


def main() -> int:
    parser = argparse.ArgumentParser(prog="radar")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="apply database migrations")
    ingest = commands.add_parser("ingest", help="pull advisories and enrichment data")
    # 3 days by default, so a Monday run also covers the weekend.
    ingest.add_argument("--days", type=int, default=3, help="look-back window in days")
    ingest.add_argument("--offline", metavar="SNAPSHOT_DIR", help="replay a snapshot, no network")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # httpx logs every request at INFO; that would bury the summary.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    with db.connect() as conn:
        applied = db.migrate(conn)
        if applied:
            print("Migrationen angewendet: " + ", ".join(applied))
        if args.command == "ingest":
            offline = args.offline is not None
            snapshot_dir = (
                Path(args.offline) if offline else DATA_DIR / "snapshots" / date.today().isoformat()
            )
            if offline and not snapshot_dir.is_dir():
                print(f"Snapshot-Ordner nicht gefunden: {snapshot_dir}", file=sys.stderr)
                return 1
            stats = run_ingest(conn, snapshot_dir, DATA_DIR / "cache", args.days, offline)
            print(german_summary(stats, snapshot_dir, args.days, offline))
    return 0


def german_summary(stats: IngestStats, snapshot_dir: Path, days: int, offline: bool) -> str:
    if offline:
        source = f"Offline-Wiedergabe aus {snapshot_dir.as_posix()}"
    else:
        source = f"Live-Abruf, Zeitfenster: letzte {days} Tage"
    lines = [
        "",
        "Schwachstellen-Radar: Erfassung abgeschlossen",
        "=" * 45,
        source,
        "",
        "BSI-Sicherheitshinweise (CERT-Bund WID)",
        f"  im Zeitfenster:              {stats.feed_entries:>6}",
        f"  neu:                         {stats.new_advisories:>6}",
        f"  aktualisiert (neue Version): {stats.updated_advisories:>6}",
        f"  unverändert:                 {stats.unchanged_advisories:>6}",
    ]
    if stats.skipped_tlp:
        lines.append(f"  übersprungen (nicht TLP:WHITE): {stats.skipped_tlp:>3}")
    if stats.failed_documents:
        lines.append(f"  nicht abrufbar:              {stats.failed_documents:>6}")
    lines += [
        "",
        "Anreicherung",
        f"  CVEs im Zeitfenster:         {stats.cves_in_window:>6}",
        f"  davon mit EPSS-Wert (FIRST): {stats.epss_scores:>6}",
        f"  davon in CISA KEV gelistet:  {stats.kev_cves_in_window:>6}"
        f"   (in {stats.advisories_with_kev} Sicherheitshinweisen)",
        f"  CVSS-Werte abgefragt (EUVD): {stats.cvss_looked_up:>6}   (gefunden: {stats.cvss_found})",
        f"  KEV-Katalog gesamt:          {stats.kev_catalog_size:>6}",
        "",
        f"HTTP-Anfragen: {stats.http_requests}",
    ]
    if not offline:
        lines.append(f"Snapshot gespeichert unter: {snapshot_dir.as_posix()}")
    if stats.problems:
        lines += ["", f"Probleme ({len(stats.problems)}):"]
        lines += [f"  - {problem}" for problem in stats.problems[:10]]
        if len(stats.problems) > 10:
            lines.append(f"  ... und {len(stats.problems) - 10} weitere")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
