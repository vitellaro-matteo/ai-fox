"""BSI CERT-Bund WID advisories in CSAF 2.0 format.

Written against the real samples in data/samples/bsi_csaf/. What those samples
showed, and what this parser therefore does NOT expect:
- no `scores`, `remediations` or `threats` in `vulnerabilities[]`
- `product_status` only has `known_affected` and (rarely) `last_affected`
- version ranges are BSI free text ("<7.2.12"), stored as text and interpreted later
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from radar.sources.fetcher import Fetcher

log = logging.getLogger(__name__)

FEED_URL = "https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json"
# Only documents that may be shared without restriction are stored.
ALLOWED_TLP = {"WHITE", "CLEAR"}
CVE_SCHEME = "https://www.cve.org"


@dataclass
class FeedEntry:
    advisory_id: str
    url: str
    updated: datetime
    published: datetime
    title: str


@dataclass
class Product:
    product_id: str
    vendor: str
    product_name: str
    node_category: str  # product_name | product_version | product_version_range
    version_text: str  # '' when the node carries no version
    full_name: str
    cpe: str | None
    is_fixed_node: bool


@dataclass
class Vulnerability:
    cve: str | None
    known_affected: list[str]
    last_affected: list[str]


@dataclass
class Advisory:
    advisory_id: str
    version: int
    title: str
    severity_text: str | None
    tlp: str
    initial_release_date: datetime
    current_release_date: datetime
    revision_summary: str | None
    attack_summary: str | None
    product_description: str | None
    source_url: str
    portal_url: str | None
    references: list[dict]
    products: list[Product] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def cves(self) -> set[str]:
        return {v.cve for v in self.vulnerabilities if v.cve}


def parse_feed(feed: dict) -> list[FeedEntry]:
    entries = []
    for entry in feed["feed"].get("entry", []):
        entries.append(
            FeedEntry(
                advisory_id=entry["id"],
                url=entry["content"]["src"],
                updated=datetime.fromisoformat(entry["updated"]),
                published=datetime.fromisoformat(entry["published"]),
                title=entry["title"],
            )
        )
    return entries


def parse_document(doc: dict) -> Advisory:
    document = doc["document"]
    tracking = document["tracking"]
    notes = {note.get("title"): note["text"] for note in document.get("notes", [])}
    references = document.get("references", [])

    source_url = portal_url = None
    for ref in references:
        if ref.get("category") != "self":
            continue
        if ref["url"].endswith(".json"):
            source_url = ref["url"]
        else:
            portal_url = ref["url"]

    # The last history entry explains why this revision exists
    # ("Exploit aufgenommen", "Neue Updates von Dell aufgenommen", ...).
    history = sorted(tracking.get("revision_history", []), key=lambda rev: rev["date"])

    advisory = Advisory(
        advisory_id=tracking["id"],
        version=int(tracking["version"]),
        title=document["title"],
        severity_text=document.get("aggregate_severity", {}).get("text"),
        tlp=document["distribution"]["tlp"]["label"],
        initial_release_date=datetime.fromisoformat(tracking["initial_release_date"]),
        current_release_date=datetime.fromisoformat(tracking["current_release_date"]),
        revision_summary=history[-1]["summary"] if history else None,
        attack_summary=notes.get("Angriff"),
        product_description=notes.get("Produktbeschreibung"),
        source_url=source_url or "",
        portal_url=portal_url,
        references=references,
    )
    _collect_products(doc.get("product_tree", {}).get("branches", []), "", "", advisory.products)
    for vuln in doc.get("vulnerabilities", []):
        status = vuln.get("product_status", {})
        advisory.vulnerabilities.append(
            Vulnerability(
                cve=vuln.get("cve"),
                known_affected=status.get("known_affected", []),
                last_affected=status.get("last_affected", []),
            )
        )
    return advisory


def _collect_products(branches: list, vendor: str, product_name: str, out: list[Product]) -> None:
    """Walks the product tree. Shapes seen in real documents:

    vendor > product_name                           (product without a version)
    vendor > product_name > product_version
    vendor > product_name > product_version_range
    vendor > product_name > product_name            (a "no version" node next to versions)
    """
    for branch in branches:
        category = branch["category"]
        name = branch["name"]
        if category == "vendor":
            _collect_products(branch.get("branches", []), name, "", out)
            continue

        # The outermost product_name is the product; nodes below it are versions.
        is_version_node = category in ("product_version", "product_version_range")
        this_product = product_name or name

        if "product" in branch:
            product = branch["product"]
            out.append(
                Product(
                    product_id=product["product_id"],
                    vendor=vendor,
                    product_name=this_product,
                    node_category=category,
                    version_text=name if is_version_node else "",
                    full_name=product["name"],
                    cpe=product.get("product_identification_helper", {}).get("cpe"),
                    is_fixed_node=product["product_id"].endswith("-fixed"),
                )
            )
        _collect_products(branch.get("branches", []), vendor, this_product, out)


def load_feed(fetcher: Fetcher, cache_dir: Path, since: datetime) -> list[FeedEntry]:
    """Returns the feed entries updated at or after `since`.

    The full feed is 45 MB, so the live download is conditional (ETag) and kept
    in a local cache. The snapshot only gets the entries inside the time window:
    that is all an offline replay needs.
    """
    snapshot_file = fetcher.snapshot_dir / "bsi_csaf" / "feed.json"
    if fetcher.offline:
        if not snapshot_file.exists():
            return []
        return parse_feed(json.loads(snapshot_file.read_text(encoding="utf-8")))

    cached_feed = cache_dir / "bsi-wid-white.json"
    cached_etag = cache_dir / "bsi-wid-white.etag"
    headers = {}
    if cached_feed.exists() and cached_etag.exists():
        headers["If-None-Match"] = cached_etag.read_text(encoding="utf-8")

    response = fetcher.get_response(FEED_URL, headers)
    if response.status_code == 304:
        log.info("WID feed unchanged since last download (HTTP 304)")
    else:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached_feed.write_bytes(response.content)
        cached_etag.write_text(response.headers.get("etag", ""), encoding="utf-8")

    feed = json.loads(cached_feed.read_text(encoding="utf-8"))
    feed["feed"]["entry"] = [
        entry
        for entry in feed["feed"].get("entry", [])
        if datetime.fromisoformat(entry["updated"]) >= since
    ]
    snapshot_file.parent.mkdir(parents=True, exist_ok=True)
    snapshot_file.write_text(json.dumps(feed, ensure_ascii=False), encoding="utf-8")
    return parse_feed(feed)


def load_document(fetcher: Fetcher, entry: FeedEntry) -> dict | None:
    return fetcher.get_json(entry.url, f"bsi_csaf/docs/{entry.advisory_id.lower()}.json")
