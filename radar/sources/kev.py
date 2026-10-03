"""CISA Known Exploited Vulnerabilities catalog: one JSON file, about 1,700 entries."""

from dataclasses import dataclass
from datetime import date

from radar.sources.fetcher import Fetcher

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KevEntry:
    cve: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    due_date: date | None
    ransomware_use: str | None


def parse_kev(catalog: dict) -> tuple[str, list[KevEntry]]:
    """Returns (catalog version, entries)."""
    entries = []
    for item in catalog["vulnerabilities"]:
        due = item.get("dueDate")
        entries.append(
            KevEntry(
                cve=item["cveID"],
                vendor_project=item["vendorProject"],
                product=item["product"],
                vulnerability_name=item["vulnerabilityName"],
                date_added=date.fromisoformat(item["dateAdded"]),
                due_date=date.fromisoformat(due) if due else None,
                ransomware_use=item.get("knownRansomwareCampaignUse"),
            )
        )
    return catalog["catalogVersion"], entries


def load_kev(fetcher: Fetcher) -> tuple[str, list[KevEntry]] | None:
    catalog = fetcher.get_json(KEV_URL, "kev/known_exploited_vulnerabilities.json")
    return parse_kev(catalog) if catalog else None
