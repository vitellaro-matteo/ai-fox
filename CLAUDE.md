# CLAUDE.md – project conventions

Schwachstellen-Radar: BSI advisories → match against customer inventories →
deterministic priority → German ticket and notice from templates → analyst approval in n8n.
Interview demo; feature freeze **2026-10-12**, presentation 2026-10-16.

## Hard rules

- **Never `git commit` or `git push`.** Leave changes uncommitted. At the end of each
  phase give: summary, full `git status --porcelain`, suggested commit grouping.
- **Never invent API fields or formats.** Check `data/samples/` first; if something is
  missing, fetch a real sample. Reality beats the brief, so report differences.
- **Phases end with a stop.** Wait for Matteo's OK before starting the next phase.
- No secrets in files. `.env` is gitignored; new variables go into `.env.example`.
- No EUVD data in git (D-008).

## Model test safety (a test crashed the PC on 2026-10-01, D-025)

- **Ask Matteo before loading any model.** No unattended or background model tests.
- Check free RAM first; abort if less than model size + 2 GB is free.
- Use a small context (4096) and `OLLAMA_MAX_LOADED_MODELS=1`.
- Run each test with a hard timeout and stop the Ollama server afterwards.
- Use `scripts/model_fit_test.py <model> --confirmed`; it enforces these rules.
- Local models: at most about 4 GB download, stored on C: (SSD). Never `gpt-oss:20b`
  locally; it is the Groq model only (D-016).

## Language

- Code, comments, commit messages, docs in `docs/`: **English**.
- Anything a user or customer sees (tickets, notices, dashboard, approval mails,
  README intro, `make ingest` summary): **German**.

## Code style

- Simple and explicit over clever. Matteo must be able to explain every line live.
- Comment *why*, not *what*.
- Plain SQL with psycopg, no ORM (D-014).
- LLM calls only in `radar/llm/`, never in n8n AI nodes (D-012). Model names from env.
- Zero cost: providers are local Ollama (default; demo and real customer data) and the
  Groq free tier (option B; dev and eval only). No paid API. Missing `GROQ_API_KEY`
  means fall back to Ollama without an error. The live demo never calls Groq (D-015).
- Same prompts, same JSON schema, same Pydantic validation for every provider.
  Validation fails: retry once, then `needs_review` (D-022).
- LLM calls are the last resort: prefilter, deterministic check, cache by input hash,
  revision diff first. Log how many calls each stage avoided (D-023).
- Tickets and notices come from deterministic templates. The LLM writes only the short
  German summary. Every fact must come from the advisory or the inventory (D-021).
- Real cost is 0 EUR. Cloud cost appears only as a labeled hypothetical estimate (D-024).
  No euro caps; eval runs are capped by `EVAL_GROQ_MAX_REQUESTS` (D-013).
- All HTTP to data sources goes through `radar/sources/fetcher.py` (snapshots, D-020).
- Priority is computed in code from `config/scoring.yaml`. The LLM never decides it.
- When unsure (thresholds, legal points, vendor versioning quirks): make it
  configurable, write it down as an ASSUMPTION in `docs/DECISIONS.md`, and flag it.
- Ambiguous version / release-line matches → `needs_review`, never a guess (D-005).

## Keep these files current

- `docs/DECISIONS.md`: one entry per non-trivial decision (D-NNN).
- `docs/LEARNING.md`: per component, a plain explanation plus 3–5 interview Q&As.
- `data/samples/README.md`: provenance of every sample.

## Environment

- Windows host: Python 3.10, `mingw32-make`, no GNU make. Every Makefile target must
  also work as `python scripts/tasks.py <target>` (stdlib only, Python 3.10-compatible).
- Service code runs in Docker (Python 3.12, uv). Open files with `encoding="utf-8"`
  (the Windows default codepage garbles German umlauts).
- Local LLM: host Ollama at `http://host.docker.internal:11434`. This PC: 16 GB RAM,
  Ryzen 5 3600, Radeon RX 5700 (8 GB VRAM, used by Ollama through Vulkan); C: is the
  SSD, D: and E: are one hard disk. A second, weaker laptop will be used too.

## Layout

```
radar/            Python package (cli.py, ingest.py, api/, sources/, versions/, inventory/, match/, score/, llm/, drafting/, db/, dashboard/)
db/init/          Postgres init: creates schemas n8n + radar
prompts/          versioned prompt files
config/           scoring.yaml, vendor_aliases.yaml, roi_assumptions.yaml, hypothetical_cloud_prices.yaml
data/samples/     real API samples (committed, except EUVD)
data/snapshots/   daily raw pulls (gitignored); demo/ is the one committed snapshot
data/inventory/   synthetic customer inventories + labels.json
n8n/workflows/    exported workflow JSON
eval/             datasets, runner, report
scripts/          tasks.py (task runner), model_fit_test.py (safe local model test)
docs/             ARCHITECTURE, DECISIONS, LEARNING, DEMO
```
