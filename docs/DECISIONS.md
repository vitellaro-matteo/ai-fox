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
**Open point.** EUVD parser tests need a committed fixture. Proposal: a hand-written
fixture with the real field names and formats but neutral values, marked as such.

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

## D-013 – Hard cost cap per eval run
*2026-09-30 · approved by Matteo*

`EVAL_COST_CAP_EUR` (default 5). The eval runner adds up the estimated cost after
every LLM call and aborts the run when the cap is reached. Spend is logged per run.
Prices live in config, so the cap is only as accurate as those prices. Since D-015
both configured providers cost 0 EUR, so the cap only matters if a paid provider is
added later. It stays in, because "we forgot the cap" is a bad surprise.

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
**Open point.** The kickoff brief named the Anthropic API as the default provider. The
zero-cost plan replaces it. A paid provider can be added later behind the same
interface; nothing in the design prevents it.

## D-016 – One open-weight model for both providers: gpt-oss-20b (fit on 16 GB unproven)
*2026-10-01 · model choice needs Matteo's confirmation after a fit test*

**Context.** For the "same model, cloud or on-premise" comparison, the model must exist
on Groq's free tier and in the Ollama library. Checked on 2026-10-01:
- Groq free-tier chat models: `openai/gpt-oss-20b`, `openai/gpt-oss-120b`,
  `openai/gpt-oss-safeguard-20b`, `qwen/qwen3.8-27b` (preview). The Llama models are
  listed with enterprise pricing only and are not in the free rate-limit table.
- Strict JSON-schema output on Groq: `gpt-oss-20b`, `gpt-oss-120b`, `qwen3.8-27b`.
- Ollama: `gpt-oss:20b` is a 14 GB download; `gpt-oss:120b` is 65 GB.

**Choice.** `openai/gpt-oss-20b` on Groq and `gpt-oss:20b` on Ollama. It is the smallest
model that exists on both sides, and the only realistic one for a laptop.
**Risk, not yet resolved.** Matteo's laptop has 16 GB RAM, a Ryzen 5 3600, and a
Radeon RX 5700, which is not on Ollama's list of supported AMD cards for Windows (that
list starts at the RX 7000 series; newer Ollama versions may use it through Vulkan). A
14 GB model next to Windows and the Docker stack (WSL2 may take up to 8 GB) will very
likely not fit in memory at the same time. Drive C: also has only 10 GB free, so the
model cannot even be downloaded to the default folder.
**Plan.** Test before building on it: (1) move the Ollama model folder to D: or E:,
(2) update Ollama from 0.17.1, (3) pull the model, (4) measure load time, memory and
seconds per call with the stack stopped and with it running.
**Fallbacks if it does not fit.**
- (a) Run the local half of the comparison with the Docker stack stopped. The eval only
  needs the frozen pairs and the model, and the demo uses cached results anyway.
- (b) Give up "same model": Groq `gpt-oss-20b` versus a smaller local model. The slide
  then compares two different models, which is a weaker statement.

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

**Trade-off.** An eval with more than about 200 LLM calls takes more than one day on
Groq. The eval set has to be sized with that in mind, and the deterministic stage has
to resolve as much as possible first.

## D-018 – Phase 4 comparison: same model on Groq and on local Ollama
*2026-10-01 · decided by Matteo*

This replaces the "cloud model versus local model" comparison of the kickoff brief. The
same frozen pairs run through `gpt-oss-20b` on Groq and on Ollama. The report shows:
agreement (the share of pairs with the same decision, plus a table of the
disagreements), latency per call for each, and the cost: 0 EUR for both.
**Caveat to state on the slide.** "Same model" means the same published weights. Groq
and Ollama may use different quantization and different default settings, so small
differences in the answers are expected, and the agreement rate measures exactly that.
