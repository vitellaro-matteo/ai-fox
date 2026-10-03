"""FIRST EPSS: probability that a CVE is exploited in the next 30 days.

The only EPSS source in this project (D-004).
"""

from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from radar.sources.fetcher import Fetcher

EPSS_URL = "https://api.first.org/data/v1/epss"
# The API returns at most 100 rows per page by default, so one batch must not
# ask for more than 100 CVEs or rows would be cut off silently.
BATCH_SIZE = 100


@dataclass
class EpssScore:
    cve: str
    score: Decimal
    percentile: Decimal
    score_date: date


def parse_epss(response: dict) -> list[EpssScore]:
    # The API sends the numbers as strings ("0.038590000"). Decimal keeps them exact.
    return [
        EpssScore(
            cve=row["cve"],
            score=Decimal(row["epss"]),
            percentile=Decimal(row["percentile"]),
            score_date=date.fromisoformat(row["date"]),
        )
        for row in response.get("data", [])
    ]


def load_epss(fetcher: Fetcher, cves: list[str]) -> list[EpssScore]:
    """Fetches scores for the given CVEs.

    CVEs that EPSS does not know are simply missing from the answer. That is
    normal for very new CVEs and is not an error.
    """
    scores = []
    ordered = sorted(cves)
    for start in range(0, len(ordered), BATCH_SIZE):
        batch = ordered[start : start + BATCH_SIZE]
        url = f"{EPSS_URL}?cve={','.join(batch)}"
        response = fetcher.get_json(url, f"epss/batch-{start // BATCH_SIZE:04d}.json")
        if response:
            scores.extend(parse_epss(response))
    return scores
