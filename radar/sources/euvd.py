"""ENISA EUVD: used only for CVSS scores (D-001, D-002).

Fields we deliberately ignore: `epss` (it is in percent, FIRST is our EPSS
source, D-004) and the product/version lists (BSI decides affectedness, D-001).

The API answers one CVE per request, so scores are fetched only for the CVEs
that need one (D-019), never for every CVE of every advisory.
"""

from dataclasses import dataclass
from decimal import Decimal

from radar.sources.fetcher import Fetcher

EUVD_LOOKUP_URL = "https://euvdservices.enisa.europa.eu/api/enisaid"


@dataclass
class CvssScore:
    cve: str
    score: Decimal | None  # None: EUVD knows the CVE but has no score
    version: str | None  # "3.1", "4.0", ...
    vector: str | None
    source_id: str | None  # e.g. EUVD-2026-2223


def parse_euvd_record(cve: str, record: dict) -> CvssScore:
    score = record.get("baseScore")
    # Some records carry a score without a version or vector. A score whose
    # version is unknown cannot be explained, so it is treated as missing.
    version = record.get("baseScoreVersion")
    has_score = score is not None and score >= 0 and version
    return CvssScore(
        cve=cve,
        score=Decimal(str(score)) if has_score else None,
        version=version if has_score else None,
        vector=record.get("baseScoreVector") if has_score else None,
        source_id=record.get("id"),
    )


def load_cvss(fetcher: Fetcher, cve: str) -> CvssScore | None:
    """Returns the score record for one CVE, or None if EUVD does not know it."""
    record = fetcher.get_json(f"{EUVD_LOOKUP_URL}?id={cve}", f"euvd/{cve}.json")
    if not record or "id" not in record:
        return None
    return parse_euvd_record(cve, record)
