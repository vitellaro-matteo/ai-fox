# Decisions

One entry per non-trivial decision: context, options, choice, trade-off.
Entries marked **ASSUMPTION** are policy choices that Matteo may change; they
live in config, not in code.

---

## D-001 – BSI WID is the single source of truth for "is this asset affected?"
*2026-09-30 · approved by Matteo*

**Context.** Two sources describe affected products: BSI WID (CSAF) and ENISA EUVD.
They disagree. For CVE-2025-25249, WID says FortiOS `<7.4.9` is affected, EUVD says
`7.4.0 ≤7.4.7`.
**Options.** (a) WID only, (b) EUVD only, (c) merge both.
**Choice.** (a) WID decides affectedness. EUVD only supplies CVSS scores.
**Trade-off.** We may miss a product that only EUVD lists. In return there is one
explainable answer to "why is this affected?", and the German, BSI-curated source is
what a German MSP would cite towards NIS2 customers. Merging two conflicting range
sets would produce decisions nobody can explain.

## D-002 – EUVD is the required CVSS source; fallback is the BSI text rating
*2026-09-30 · approved by Matteo*

**Context.** Verified on 47 WID CSAF documents: none contains `vulnerabilities[].scores`.
The only rating is `document.aggregate_severity.text` (`niedrig` / `mittel` / `hoch`;
`kritisch` is expected but not yet seen in a sample). The priority rules need CVSS.
**Options.** EUVD (`/api/search`, ~1,100 records per day, `baseScore` on every record),
NVD (strict rate limit, API key), or the BSI text rating only.
**Choice.** EUVD. If a CVE has no EUVD score: `hoch` counts as ≥ 7.0 and `kritisch`
as ≥ 9.0. The explanation text then says *"Schätzung aus BSI-Einstufung"*. NVD stays
unused.
**Trade-off.** EUVD becomes a hard dependency of scoring. If it is down, the fallback
keeps the pipeline running with coarser scores. That is visible in the explanation, not hidden.

## D-003 – CVSS version is stored and shown with every score
*2026-09-30 · approved by Matteo*

**Context.** EUVD returns a mix of CVSS 3.1 and 4.0 (field `baseScoreVersion`; 8 of
100 records in one sample had no version/vector). The two versions are not the same
scale semantically, even though both go from 0 to 10.
**Choice.** Store `cvss_score`, `cvss_version`, `cvss_vector`, `cvss_source`
(`euvd` | `bsi_estimate`). Every explanation names the version, e.g. *"CVSS 9.8
(v3.1)"*. The thresholds in `scoring.yaml` are applied to both versions alike, and
the explanation and LEARNING.md say so openly.
**Trade-off.** One threshold for two scales is a simplification. Separate thresholds
per version would be more precise but would need calibration data we don't have.

## D-004 – FIRST is the only EPSS source
*2026-09-30 · approved by Matteo*

**Context.** EUVD also has an `epss` field, but in **percent** (3.86), while FIRST
returns a probability as a string (`"0.038590000"`). Mixing them silently would be
off by a factor of 100.
**Choice.** Use FIRST only and ignore EUVD's `epss`. Batches of at most 100 CVEs,
because the FIRST default page size is 100 and unknown CVEs are silently omitted, so
a missing CVE means "no EPSS", not an error.

## D-005 – Version ranges are interpreted per release line; ambiguity → `needs_review`
*2026-09-30 · approved by Matteo*

**Context.** WID ranges are BSI free text, not the CSAF `vers:` syntax. Examples seen:
`<7.2.12`, `<=26.08.0`, `<7.2.12 UPN IFN`, `Appliance <1.2.3.4`, `<3.1-rc2`. The FortiOS
advisory lists `<7.2.12`, `<7.4.9` and `<7.6.4` side by side. Read naively,
FortiOS 7.2.13 would be "affected" because 7.2.13 < 7.4.9. That is wrong: 7.2.13 is
the fixed line.
**Choice.** Group the ranges of one product by release line (major.minor). An asset
version is compared only with the range of its own line. If its line has no range,
or the range text cannot be parsed, the result is `needs_review`, never a guess.
**Trade-off.** Some real matches go to the human queue. That is the intended
behaviour: a false "not affected" is the expensive error.

## D-006 – Fixed versions come from the product tree, not from `product_status`
*2026-09-30*

**Context.** Across all samples `product_status` only contains `known_affected`
(and rarely `last_affected`). There is no `fixed` or `known_not_affected` list. Fixed
versions appear only as product nodes whose `product_id` ends in `-fixed`, and no
status list references them. One real quirk: in the poppler advisory the `-fixed`
node carries the range name `<=26.08.0`.
**Choice.** Read the `-fixed` nodes as "first fixed version of this line" when their
name parses as a plain version; otherwise ignore them and rely on the range.

## D-007 – Revisions: re-match every revision, re-run the LLM only on changed products
*2026-09-30 · approved by Matteo*

**Context.** In the last 90 days WID published 1,458 new advisories but 2,750
updates. The OpenSSL advisory WID-SEC-W-2026-0234 is at revision 60 with 117
products, because vendors keep being added. A newly added vendor can make a customer
affected, so updates must be matched again.
**Choice.** Store every revision (key: tracking ID + version). On a new revision, diff
its product tree against the previous stored revision. Deterministic matching runs on
everything (cheap). The LLM runs only on candidates whose product is new or changed;
unchanged candidates reuse the stored decision. Log the number of LLM calls saved.
**Trade-off.** A changed prompt or model does not automatically re-judge old
products. The eval harness does that explicitly instead.

## D-008 – Snapshots: one curated demo snapshot in git; no EUVD data in git
*2026-09-30 · approved by Matteo*

**Context.** A full WID feed pull is 45 MB. EUVD's API documentation and website state
no licence or reuse terms (checked 2026-09-30). The EU reuse decision 2011/833/EU
(CC BY 4.0) covers Commission documents, and it is not clear that it covers ENISA.
EUVD records also contain third-party text (VulDB, vendors). BSI TLP:WHITE may be
shared without restriction. KEV is a US government work. FIRST asks for attribution
of EPSS.
**Choice.** Daily raw pulls (`data/snapshots/YYYY-MM-DD/`) are gitignored. Exactly
one curated snapshot, `data/snapshots/demo/`, is committed, with BSI, KEV and EPSS
only. EUVD data is never committed. This includes the parser samples in
`data/samples/euvd/`. The offline demo rebuilds EUVD scores from a local,
uncommitted cache.
**Trade-off.** A clean clone cannot run the offline demo with exact EUVD scores
until one online run has filled the cache. Without the cache the BSI fallback (D-002)
applies, and the dashboard shows this.
**EUVD parser tests.** The committed fixture `tests/fixtures/euvd_record_synthetic.json`
is hand-written: real field names and formats, neutral values, and marked as such. A
second test runs against the real local sample when it exists and is skipped otherwise.

## D-009 – One task runner for make and plain Python
*2026-09-30 · approved by Matteo*

**Context.** Matteo's laptop runs Windows, which has `mingw32-make` but no GNU make.
**Choice.** Every Makefile target forwards to `python scripts/tasks.py <target>`.
The runner uses the standard library only (runs on the host Python 3.10) and executes
the real work inside the container. `make test` falls back to a throwaway uv
container when uv is not installed on the host.
**Trade-off.** One extra indirection. In return the commands are identical on Windows,
macOS and Linux.

## D-010 – Pinned image versions
*2026-09-30*

n8n `2.41.4` (current stable on 2026-09-30), Postgres `17.11`, Mailpit `v1.31.3`,
Python `3.12.14-slim`, uv `0.12.21`, Ollama `0.35.0`. Reason: the demo must not
change behaviour because a `latest` tag moved during the two weeks before the talk.

## D-011 – Local LLM: host Ollama by default, container as fallback
*2026-09-30 · approved by Matteo*

**Context.** Ollama is installed on Matteo's Windows host. On Windows, Docker
containers cannot use the host GPU easily, and the host install is simpler anyway.
**Choice.** `OLLAMA_BASE_URL=http://host.docker.internal:11434` by default. The
compose profile `local-llm` remains for machines without a host Ollama (on port 11435,
so the two cannot clash).

## D-012 – LLM calls live in radar-api, not in n8n AI nodes; model names come from env
*2026-09-30 · from the kickoff brief*

**Choice.** All prompts, LLM calls, validation and cost logging are Python code in
`radar/llm/`. n8n owns the process: scheduling, branching, waiting for the human,
retries, notifications. Model names come from `OLLAMA_MODEL` / `GROQ_MODEL` (see D-015).
**Why.** Versioned prompts, unit tests, one eval harness, one place to swap providers.
**Trade-off.** The n8n canvas shows an HTTP call instead of a visible "AI" node. The
slide has to explain where the AI sits.

## D-013 – Cap on Groq requests per eval run (replaces the euro cost cap)
*2026-09-30 · revised 2026-10-03 by Matteo*

**Context.** The first version of this entry was a hard cost cap in euros. Since the
zero-cost plan (D-015) the real cost is always 0 EUR, so a euro cap can never trigger
and only confuses.
**Choice.** `EVAL_GROQ_MAX_REQUESTS` (default 200) limits how many Groq requests one eval
run may make. When the cap is reached, the run stops cleanly and can be resumed later
(D-017). The number of requests used is logged per run.
**Why 200.** **ASSUMPTION:** Groq's free tier allows 1,000 requests and 200,000 tokens
per day for the model; at roughly 1,000 tokens per call the token limit is reached after
about 200 calls. The default keeps one run inside one day's free budget and leaves the
rest of the day's requests for development. Adjust it once phase 2 has measured the real
tokens per call.

## D-014 – Plain SQL and psycopg instead of an ORM
*2026-09-30*

**Choice.** Tables are defined in numbered SQL migration files (`radar/db/migrations/`)
and accessed with psycopg 3 and explicit SQL.
**Why.** Every query can be shown and explained in the interview. An ORM would hide the
queries that produce the audit trail.
**Trade-off.** More code by hand for inserts and selects; no automatic model sync.

## D-015 – Zero-cost LLM setup: local Ollama is the default, Groq free tier is option B
*2026-10-01 · decided by Matteo*

**Context.** The project must cost nothing to run. Two free ways to run a model exist:
locally with Ollama, or on Groq's free tier (no credit card).
**Choice.**
- **Ollama (local) is the default provider**, for the demo and for anything that could
  hold real customer data.
- **Groq is option B**, used for speed during development and for eval runs. The key
  comes from `GROQ_API_KEY`. If the key is missing, everything uses Ollama, and this is
  logged as information, not raised as an error.
- Both providers get the same prompt files, the same JSON schema, and the same Pydantic
  validation. A provider only differs in how the request is sent.
- The live demo never calls Groq. Demo LLM results are precomputed and cached.

**Why local is the default.**
1. *Confidentiality.* A customer inventory lists which firewall, which version, and
   which system is reachable from the internet. That is a map for an attacker. With a
   local model this data never leaves the MSP's own machines. In this project the
   inventories are synthetic, but the default has to be the one that would be right
   with real data.
2. *No guarantees on a free tier.* Groq's free limits, model list and terms can change
   at any time, and there is no SLA. During this project the free model list already
   turned out smaller than expected (D-016). A process with a 24-hour reaction target
   cannot depend on that.

**Trade-off.** Local inference is slower, and on a 16 GB laptop the model choice is
tight (D-016). Development would be painfully slow without Groq, which is why it stays
as option B.
**Confirmed by Matteo on 2026-10-01:** no paid API at all. The Anthropic API named in
the kickoff brief is out. The provider abstraction stays, but only Ollama and Groq are
implemented and tested.

## D-016 – Models: gpt-oss-20b on Groq, a small model (at most about 4 GB) locally
*2026-10-01 · revised 2026-10-03 by Matteo after the fit test (D-025)*

**Context.** The first plan was one open-weight model on both sides, for a "same model,
cloud or on-premise" comparison. Checked on 2026-10-01:
- Groq free-tier chat models: `openai/gpt-oss-20b`, `openai/gpt-oss-120b`,
  `openai/gpt-oss-safeguard-20b`, `qwen/qwen3.8-27b` (preview). The Llama models are
  listed with enterprise pricing only and are not in the free rate-limit table.
- Strict JSON-schema output on Groq: `gpt-oss-20b`, `gpt-oss-120b`, `qwen3.8-27b`.
- Ollama: `gpt-oss:20b` is a 14 GB download; it is the smallest model on both sides.

**What happened.** `gpt-oss:20b` does not run on Matteo's machine (measured numbers in
D-025). His second machine, a laptop, is likely no stronger.
**Choice.**
- **Groq (development and eval): `openai/gpt-oss-20b`.** Unchanged.
- **Local (default provider): a small model**, at most about 4 GB download, that fits
  completely into the GPU (8 GB VRAM) or into about 3 GB of RAM. Candidates, sizes from
  the Ollama library on 2026-10-03: `gemma3:4b` (3.3 GB), `qwen3:4b` (2.5 GB),
  `granite4.2:3b` (2.2 GB), `phi4-mini` (2.5 GB). Selection criteria: correct decisions
  on the smoke cases, valid JSON every time, understandable German reasoning, seconds per
  call. None of the model pages states German support explicitly, so it is measured.
  **The choice is open until the candidates have been tested** with
  `scripts/model_fit_test.py`.
- `gpt-oss:20b` is dropped locally. Models are stored on C: (SSD), not on the hard disk.

**Trade-off.** "Same model on both sides" is gone. The comparison becomes "large open
model in the cloud versus small open model on a normal laptop" (D-018), which is closer
to what a Mittelstand customer would really face, but the local model will make more
mistakes. The design absorbs that: low confidence goes to `needs_review`, and the
deterministic stage decides most pairs before any model is asked (D-023).

## D-017 – Eval runner respects Groq's free-tier rate limits
*2026-10-01 · decided by Matteo*

**Context.** Free-tier limits for `openai/gpt-oss-20b` according to Groq's docs on
2026-10-01: 30 requests/minute, 1,000 requests/day, 8,000 tokens/minute, 200,000
tokens/day, counted per organization. Tokens are the tight limit: at roughly 1,000
tokens per matching call that is about 8 calls per minute and about 200 calls per day.
(The 1,000 tokens are an estimate; gpt-oss is a reasoning model and its reasoning
tokens count too. Phase 2 measures the real number.)
**Choice.**
- Limits are not hard-coded. The runner reads them from the response headers
  (`x-ratelimit-limit-*`, `x-ratelimit-remaining-*`, `x-ratelimit-reset-*`) and slows
  down before a limit is reached.
- On HTTP 429 it waits for the time given in `retry-after`, with exponential backoff as
  a fallback, and retries.
- Every finished pair is written to the database at once, so an interrupted run
  continues where it stopped. A run can therefore be spread over several days.
- The run report states how often a limit was hit and how long the run waited in total.
- One run makes at most `EVAL_GROQ_MAX_REQUESTS` requests (D-013), then stops cleanly
  and can be resumed.

**Trade-off.** An eval with more than about 200 LLM calls takes more than one day on
Groq. The eval set has to be sized with that in mind, and the deterministic stage has
to resolve as much as possible first.

## D-018 – Phase 4 comparison: large open model on Groq versus small open model locally
*2026-10-01 · revised 2026-10-03 by Matteo*

This replaces both the "cloud model versus local model" comparison of the kickoff brief
and the first version of this entry ("same model on Groq and on Ollama"), which fell
with the fit test (D-025). The same frozen pairs run through `gpt-oss-20b` on Groq and
through the small local model (D-016). The report shows, for both:
- **accuracy** against the ground truth (precision, recall, F1 for "affected"),
- **agreement** (the share of pairs with the same decision, plus a table of the
  disagreements),
- **latency** per call,
- the share routed to `needs_review`,
- and the cost: 0 EUR for both.

**What the slide can honestly say.** How much quality the small local model loses
against the large one, and what that costs in extra human review. It cannot say that
the two are equivalent.

## D-019 – CVSS is fetched on demand, not for every CVE
*2026-10-01*

**Context.** The 90-day window holds about 35,000 distinct CVEs (single Linux-kernel
advisories list up to 850). EUVD answers one CVE per request (`/api/enisaid?id=CVE-…`;
the search endpoint caps a page at 100 records and cannot filter by a CVE list).
35,000 requests against a free public service would be neither polite nor useful: a
score only matters for an advisory that touches a customer.
**Choice.** `ensure_cvss()` looks up only CVEs that have no stored answer yet. Phase 1
calls it for the KEV-listed CVEs of the ingest window. From phase 2 on, matching calls
it for the CVEs of advisories that affect at least one asset. "EUVD has no score" is
stored too, so the same CVE is not asked again.
**Trade-off.** Statistics over all advisories cannot use CVSS; they use BSI's text
rating instead. EPSS has no such limit (100 CVEs per request), so it is fetched for
every CVE in the window.
**Detail.** EUVD answers an unknown CVE with HTTP 204 and an empty body, not with 404.

## D-020 – Snapshots are written by the same code that reads them
*2026-10-01*

**Choice.** One small class (`radar/sources/fetcher.py`) does all HTTP. In live mode it
writes every response to `data/snapshots/YYYY-MM-DD/` before parsing it. In offline mode
it reads those files and makes no request. Parsing and storing are identical in both
modes. Verified: replaying a snapshot into empty tables gave the same row counts as the
live run, with 0 HTTP requests.
**Details.**
- The WID feed is 45 MB. It is downloaded with a conditional request (ETag) into
  `data/cache/`; the snapshot only keeps the entries inside the time window.
- A document is downloaded only if our stored revision is older than the feed's
  `updated` date. A daily snapshot is therefore incremental: it holds what was new that
  day. The committed demo snapshot (phase 5) will be exported as a complete set.
- The SHA-512 and signature files that BSI offers per document are not checked. TLS to
  the BSI server is the integrity guarantee here; checking would double the requests.

## D-021 – Tickets and notices come from templates; the LLM writes only a short summary
*2026-10-01 · decided by Matteo (zero-cost plan)*

**Context.** The kickoff brief had the LLM draft both texts. A small local model is
slower and less reliable at long German text than at short structured answers.
**Choice.** The technician ticket and the customer notice are built from deterministic
templates filled with structured data (affected systems, priority and its explanation,
fixed versions, source links). The LLM contributes one thing: a short plain-language
German summary of the advisory. Every fact must come from the advisory or the inventory.
**Trade-off.** The texts read more uniform. In return they cannot contain an invented
version number or measure, they cost almost no inference time, and the same input
always gives the same ticket.

## D-022 – Structured output, validated; one retry, then `needs_review`
*2026-10-01 · decided by Matteo (zero-cost plan)*

Every LLM call asks for JSON that follows a JSON schema (Groq: `response_format` with
`json_schema` and `strict: true`; Ollama: the `format` parameter with the same schema).
The answer is validated with the same Pydantic model for both providers. If validation
fails, the call is repeated once. If it fails again, the case becomes `needs_review`
with the reason recorded. The pipeline never guesses and never drops the case.

## D-023 – LLM calls are the last resort, and every avoided call is counted
*2026-10-01 · decided by Matteo (zero-cost plan)*

Order of work for each advisory × asset pair: (1) the vendor/product prefilter removes
pairs that cannot match, (2) the deterministic version check decides what it can,
(3) the cache answers pairs whose input hash was seen before, (4) the revision diff
reuses decisions for unchanged products (D-007). Only what is left goes to the LLM.
Each stage logs how many pairs it settled, so the report can state "of N pairs, the LLM
saw M". With Groq's free tier allowing roughly 200 calls a day (D-017), this is also
what makes the eval feasible.

## D-024 – Real cost is 0 EUR; a cloud cost is shown only as a labeled estimate
*2026-10-01 · decided by Matteo (zero-cost plan)*

Token counts are logged for every call. The real cost is always reported as 0 EUR.
`config/hypothetical_cloud_prices.yaml` holds public list prices; with it, the stats and
the eval report add a line "what this would cost in a paid cloud", labeled as a
hypothetical estimate, with the price source next to it. The file is optional. The
EUR/USD rate in it is an **ASSUMPTION** to adjust.

## D-025 – Fit test: gpt-oss:20b does not run on a 16 GB machine; safety rules for model tests
*2026-10-03 · measured on 2026-10-01*

**Machine.** 16 GB RAM, Ryzen 5 3600, Radeon RX 5700 (8 GB VRAM), C: SSD, D:/E: one
2 TB hard disk. Ollama 0.35.0; it uses the RX 5700 through Vulkan (7.2 GB VRAM
available), although the card is not on Ollama's list of supported AMD cards.

**Measured.**

| | llama3.2 (3B, 2.0 GB) | gpt-oss:20b (14 GB) |
|---|---|---|
| Docker stack | running | stopped |
| Free RAM before loading | 1.3 GB | 4.4 GB |
| Model stored on | hard disk (E:) | hard disk (E:) |
| Placement | 100 % GPU (2.5 GB loaded) | planned: 25 layers on GPU (6.3 GB), 16 layers in RAM |
| Load time | 31.4 s | never finished |
| Seconds per call (warm) | 4.6 s average, 5.0 s maximum | no call completed |
| Speed | about 70 tokens/s | – |
| Valid JSON | 5 of 5 | – |
| Correct decisions (5 smoke cases) | 2 of 5 | – |
| Result | runs, but too weak | attempt 1: HTTP 500 after 322 s (Ollama's 5-minute load limit). Attempt 2 (15-minute limit): the PC crashed about 90 seconds in. |

**Why it failed.** The model needs about 13 GB in total. The GPU can take 6.3 GB; the
rest, plus working memory, did not fit into 4.4 GB of free RAM, and the 14 GB file had
to be read from a hard disk. The system ran out of memory.
**What the small-model result shows.** llama3.2 was fast and always returned valid JSON,
but 3 of 5 decisions were wrong, including a Sophos firewall marked as affected by a
Fortinet advisory. Valid JSON says nothing about a correct decision. The local model
must be chosen by measured accuracy, not by speed (D-016).
**Mistake to learn from.** The second attempt ran unattended in the background with a
longer time limit, on a machine that was already short of memory. That is what turned a
failed load into a crash.

**Safety rules for every model test from now on** (also in CLAUDE.md; enforced in code
by `scripts/model_fit_test.py`):
1. Ask Matteo before loading any model. No unattended or background model tests.
2. Check free RAM first; abort if less than model size + 2 GB is free.
3. Use a small context (4096) and `OLLAMA_MAX_LOADED_MODELS=1`.
4. Run each test with a hard timeout and stop the Ollama server afterwards.

**Also noted.** The Ollama desktop app ignores the `OLLAMA_MODELS` environment variable
and uses the model folder from its own settings; only a directly started `ollama serve`
reads the variable.
