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

## 3. LLM providers: local by default, cloud as option B

**In plain words.** A language model can run in two places: on our own machine with
Ollama, or in Groq's cloud on its free tier. The code sends the same prompt and checks
the answer with the same rules in both cases. Locally a small model runs, because a
normal laptop cannot hold a large one. In the cloud the large open model gpt-oss-20b
runs. Local is the default; the cloud is only for fast development with synthetic data.

**Q: Why is the local model the default if the cloud model is faster and better?**
A: Because of what the data is. An inventory says which customer runs which firewall
version and which systems are reachable from the internet. That is exactly what an
attacker wants to know. With a local model it never leaves the MSP's own machines.
And a free tier has no guarantees: limits and the model list can change overnight,
which doesn't fit a process with a 24-hour reaction target.

**Q: Why not run the same large model locally?**
A: I tried. gpt-oss:20b needs about 13 GB of memory. On a 16 GB PC with 4.4 GB free it
never finished loading, and the second attempt crashed the machine. A small model of
2 to 3 GB runs entirely on the graphics card and answers in about 5 seconds. The
honest conclusion: on normal office hardware you get a small model, and the system
must be designed so that a small model is enough.

**Q: A small model makes more mistakes. Why is that acceptable?**
A: Three things limit the damage. Most pairs never reach the model, because the
deterministic version check decides them first. When the model is unsure, the case
goes to a human instead of being guessed. And the model never sets the priority or
sends anything. I also measure the loss instead of guessing it: the evaluation
compares the small local model with the large cloud model on the same pairs.

**Q: What did the first small-model test show?**
A: The 3B model returned valid JSON every time and was still wrong in 3 of 5 cases. It
even marked a Sophos firewall as affected by a Fortinet advisory. Valid JSON is not
the same as a correct answer, which is why accuracy is measured separately.

**Q: What happens when Groq's rate limit is hit?**
A: The eval runner reads the limits from the response headers and slows down before
reaching them. If it still gets an HTTP 429, it waits as long as the server asks and
retries. Every finished pair is saved at once, so a run can stop and continue later.
A run is also capped at a fixed number of requests, so it stays inside the daily free
budget.

**Q: What if Groq or the local model is unavailable during the live demo?**
A: Nothing happens, because the demo runs no model. Its LLM results were computed
beforehand and are replayed from a cache.

## 4. Ingestion

**In plain words.** Every morning the service asks four public sources what is new and
stores the answers. From BSI it reads a list (the "feed") of all advisories with the
date each was last changed, and downloads only those it doesn't have in that state
yet. Then it adds three facts per vulnerability: is it exploited (KEV), how likely is
exploitation (EPSS), how severe is it (CVSS, from EUVD). Every downloaded file is also
written to a dated folder, so the same day can be replayed later without the internet.

**Q: What does "idempotent" mean here, and how did you check it?**
A: Running the ingest twice gives the same database as running it once. An advisory
revision is identified by its ID plus version number; a revision we already have is
skipped. I checked it by running the same ingest twice and comparing row counts: the
second run stored nothing new and did not download a single document again.

**Q: How do you handle an advisory that gets updated?**
A: Each revision is a new row; the old one stays and is marked as not the latest.
Keeping the old revision is what later allows a diff: which products were added by
this update? Only those need to be checked again.

**Q: How do you know the offline demo shows the same thing as a live run?**
A: Both use the same code. One small class does all HTTP: in live mode it saves each
response to disk before parsing it, in offline mode it reads that file instead. I
emptied the tables, replayed a snapshot with the network unused, and got identical
row counts with zero HTTP requests.

**Q: Why don't you fetch CVSS scores for every CVE?**
A: Ninety days of advisories contain about 35,000 different CVEs, and EUVD answers one
CVE per request. A score only matters when an advisory actually touches a customer
system, so scores are fetched on demand and remembered. EPSS allows 100 CVEs per
request, so there we simply fetch all.

**Q: What does "being a good citizen" towards these APIs mean in code?**
A: A User-Agent that names the tool and a contact, at least half a second between two
requests to the same host, timeouts, at most four attempts with growing waits, and no
retry on errors that won't go away (like a 403). The 45 MB BSI feed is downloaded only
when it has changed (the server tells us through an ETag).

**Q: What if one source is down in the morning?**
A: The run continues. A failed document or source is listed under "Probleme" in the
summary and recorded with the run. KEV keeps yesterday's catalog, and a missing CVSS
later falls back to BSI's own text rating.
