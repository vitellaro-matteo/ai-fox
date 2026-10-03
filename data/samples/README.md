# Real data samples

Fetched on **2026-09-30** with the User-Agent `Schwachstellen-Radar/0.1`. Parsers
and their tests are written against these files. Never edit them by hand; re-fetch
instead.

| File | Source URL | Notes |
|---|---|---|
| `bsi_csaf/provider-metadata.json` | https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json | Lists 6 ROLIE feeds (3× WHITE, 3× GREEN). We use only `bsi-wid-white`. |
| `bsi_csaf/feed-bsi-wid-white.excerpt.json` | …/csaf/white/bsi-wid-white.json | First 25 of 13,823 entries. The full feed is 45 MB and sends ETag/Last-Modified. |
| `bsi_csaf/feed-bsi-cvd-white.json` | …/csaf/white/bsi-cvd-white.json | 8 entries (coordinated disclosure). Kept to show that it is a different feed. |
| `bsi_csaf/wid-sec-w-2026-0085.json` | …/white/2026/wid-sec-w-2026-0085.json | FortiOS. Release-line ranges `<7.2.12`, `<7.4.9` …; revision 2 "Exploit aufgenommen"; CVE in KEV. |
| `bsi_csaf/wid-sec-w-2026-0234.json` | …/white/2026/wid-sec-w-2026-0234.json | OpenSSL, revision 60, 117 products from many vendors. |
| `bsi_csaf/wid-sec-w-2026-0661.json` | …/white/2026/wid-sec-w-2026-0661.json | Windows / Windows Server, 48 CVEs, versions as feature releases (22H2), no builds. |
| `bsi_csaf/wid-sec-w-2026-1712.json` | …/white/2026/wid-sec-w-2026-1712.json | Veeam Backup & Replication, 4-part version range. |
| `bsi_csaf/wid-sec-w-2026-2273.json` | …/white/2026/wid-sec-w-2026-2273.json | Kyocera printers: model list, no firmware versions. |
| `bsi_csaf/wid-sec-w-2026-3268.json` | …/white/2026/wid-sec-w-2026-3268.json | Exchange Server: CU encoded in the product name. |
| `bsi_csaf/wid-sec-w-2026-3463.json` | …/white/2026/wid-sec-w-2026-3463.json | Synology DSM, versions like `7.3.2-86009-4`. |
| `bsi_csaf/wid-sec-w-2026-3674.json` | …/white/2026/wid-sec-w-2026-3674.json | poppler: `last_affected` status, `<=` range, `-fixed` node with a range name. |
| `bsi_csaf/wid-sec-w-2026-3605.json` | …/white/2026/wid-sec-w-2026-3605.json | Red Hat: nested `product_name > product_name` branch. |
| `bsi_csaf/wid-sec-w-2026-3671.json` | …/white/2026/wid-sec-w-2026-3671.json | Moodle: a vulnerability entry with no CVE. |
| `kev/kev.excerpt.json` | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Header + first 30 of 1,730 entries. |
| `epss/epss_batch.json` | https://api.first.org/data/v1/epss?cve=… | 5 CVEs requested, 4 returned: unknown CVEs are silently omitted. |
| `euvd/*` | https://euvdservices.enisa.europa.eu/api/… | **Gitignored** (no reuse licence, see D-008). |

All BSI files are TLP:WHITE.
