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
retries, notifications. Model names come from `LLM_MODEL_MATCH` / `LLM_MODEL_DRAFT`.
**Why.** Versioned prompts, unit tests, one eval harness, one place to swap providers.
**Trade-off.** The n8n canvas shows an HTTP call instead of a visible "AI" node. The
slide has to explain where the AI sits.

## D-013 – Hard cost cap per eval run
*2026-09-30 · approved by Matteo*

`EVAL_COST_CAP_EUR` (default 5). The eval runner adds up the estimated cost after
every LLM call and aborts the run when the cap is reached. Spend is logged per run.
Prices live in config, so the cap is only as accurate as those prices.

## D-014 – Plain SQL and psycopg instead of an ORM
*2026-09-30*

**Choice.** Tables are defined in numbered SQL migration files (`radar/db/migrations/`)
and accessed with psycopg 3 and explicit SQL.
**Why.** Every query can be shown and explained in the interview. An ORM would hide the
queries that produce the audit trail.
**Trade-off.** More code by hand for inserts and selects; no automatic model sync.
