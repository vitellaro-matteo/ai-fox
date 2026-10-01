# Learning notes

For each component: a plain-language explanation, then questions an interviewer
might ask, with good answers. This file grows with every phase.

---

## 1. Overall architecture

**In plain words.** n8n runs the process: when to start, what happens next, and
waiting for the analyst's click. A small Python service does the thinking work:
fetching advisories, comparing them with the customers' systems, computing
priorities, and talking to the LLM. Postgres stores everything, Mailpit catches every
e-mail so nothing real is sent.

**Q: Why not build everything in n8n, with its AI nodes?**
A: The matching logic needs unit tests, versioned prompts, and an evaluation harness
that runs the same code on thousands of pairs. That's much easier in Python. n8n is
strong exactly where Python is tedious: schedules, waiting for a human, retries,
visible process flow. Each tool does what it is good at.

**Q: Why one Postgres with two schemas instead of two databases?**
A: One container, one backup, one place to look. The schemas keep n8n's internal
tables and our data apart, so a reset of our data never touches n8n.

**Q: What happens if the LLM provider is down?**
A: Deterministic matching and scoring still run. Only the cases that need the LLM
wait, and they are not dropped: they end up in the review queue.

## 2. Data sources

**In plain words.** BSI CERT-Bund publishes security advisories (WID) in German, in
the standard machine-readable format CSAF. They tell us *which products and versions*
are affected. CISA's KEV list tells us which vulnerabilities are *actually exploited*.
FIRST's EPSS gives a *probability of exploitation* in the next 30 days. ENISA's EUVD
provides the *CVSS severity score*, which BSI's CSAF files don't contain.

**Q: Why BSI and not NVD as the main source?**
A: It's the German national source, in German, curated, and a German MSP would cite
it to NIS2 customers. It also lists affected products per vendor in one document.
NVD is rate-limited, and we'd mainly need it for CPE identifiers. BSI already gives
CPEs for explicit product versions (not for ranges), which is enough for our matching.

**Q: What surprised you about the real data?**
A: Three things. First, BSI's CSAF files have no CVSS scores at all, so we pull them
from EUVD. Second, version ranges are free text per release line, like "<7.2.12" and
"<7.4.9" side by side; compared naively, a fixed 7.2.13 would look affected. Third,
updates outnumber new advisories almost two to one: vendors are added to old
advisories over months.

**Q: Two sources disagree about affected versions. What do you do?**
A: One source decides: BSI. EUVD only provides the score. If I merged the ranges, no
one could explain afterwards why a system was marked affected.

**Q: Why does TLP matter?**
A: TLP (Traffic Light Protocol) says who may receive a document. We only store
TLP:WHITE/CLEAR, which may be shared freely. BSI also has TLP:GREEN feeds, which we
deliberately skip.

**Q: Why isn't EUVD data in the git repository?**
A: EUVD publishes no licence for reuse, and its records contain third-party text. When
the right to redistribute is unclear, we keep the data in a local cache and don't
publish it.
