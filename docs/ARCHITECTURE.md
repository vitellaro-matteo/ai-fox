# Architecture

**Design principle:** the LLM translates language into structure; deterministic code
decides; a human approves.

## Components

```mermaid
flowchart LR
    subgraph ext["External sources (read-only)"]
        WID["BSI CERT-Bund WID<br/>CSAF 2.0, TLP:WHITE<br/><i>affected products</i>"]
        KEV["CISA KEV<br/><i>known exploited</i>"]
        EPSS["FIRST EPSS<br/><i>exploit probability</i>"]
        EUVD["ENISA EUVD<br/><i>CVSS scores</i>"]
    end

    subgraph stack["docker compose (local)"]
        N8N["n8n<br/>process: schedule, branching,<br/>waiting for approval, retries"]
        API["radar-api (FastAPI)<br/>ingest · match · score ·<br/>LLM · drafts · dashboard"]
        PG[("Postgres<br/>schema n8n<br/>schema radar")]
        MAIL["Mailpit<br/>catches every mail"]
    end

    LLM["LLM (gpt-oss-20b)<br/>host Ollama = default<br/>Groq free tier = option B"]
    INV["Customer inventories<br/>CSV / JSON<br/>(synthetic)"]
    ANALYST(("Analyst"))

    WID & KEV & EPSS & EUVD -->|HTTP, polite UA,<br/>snapshots to disk| API
    INV -->|importer| API
    N8N -->|HTTP calls| API
    API <-->|SQL| PG
    N8N <-->|own tables| PG
    API -->|only unresolved candidates,<br/>no tools, schema-validated| LLM
    N8N -->|approval mail| MAIL
    MAIL --> ANALYST
    ANALYST -->|Freigeben / Ablehnen /<br/>Priorität ändern| N8N
    N8N -->|customer notice<br/>only after approval| MAIL
```

## Data flow for one advisory

```mermaid
flowchart TD
    A["New or updated WID advisory<br/>(ID + revision)"] --> B["Normalize products and versions"]
    B --> C{"Diff against previous revision"}
    C -->|unchanged products| C2["Reuse stored decisions"]
    C -->|new / changed products| D["Candidate retrieval<br/>vendor alias + fuzzy product name"]
    D --> E{"Deterministic check<br/>per release line"}
    E -->|affected / not affected| G
    E -->|cannot decide| F["LLM adjudication<br/>structured output"]
    F -->|confident| G["Decision + audit record"]
    F -->|low confidence / unknown| R["needs_review queue"]
    G -->|affected| S["Deterministic priority P1–P4<br/>KEV · EPSS · CVSS · exposure · criticality"]
    S --> T["German drafts: ticket + customer notice"]
    T --> U["n8n: approval mail to analyst"]
    R --> U
    U -->|approved| V["Ticket in radar.tickets<br/>+ customer notice to Mailpit"]
    U --> W["Analyst decision in audit trail"]
```

## Responsibilities

| Component | Owns | Does not do |
|---|---|---|
| n8n | Scheduling, branching, waiting for the human, retries, error workflow, notifications | Business logic, LLM calls, SQL on `radar` tables |
| radar-api | Ingestion, normalization, matching, scoring, LLM calls, drafts, dashboard, eval | Sending mail to customers (n8n does it, after approval) |
| LLM | Language → structure: fuzzy product matching, German summaries, draft texts | Priority, sending, any action on a system |
| Analyst | The final decision for every ticket and every customer notice | – |

## Where the trust boundaries are

- **Advisory and inventory text is untrusted input.** It reaches the LLM only inside
  delimiters, marked as data. The LLM has no tools, and its output must pass a
  Pydantic schema.
- **Customer data stays local by default.** The default LLM provider is the local
  Ollama. Groq is only used for development and eval runs on synthetic data (D-015).
- **Priority is computed in code** from `config/scoring.yaml`. An LLM answer cannot
  change it.
- **Nothing reaches a customer without a logged approval.** The only path to a customer
  mail goes through the n8n approval step.

## Ports (all bound to 127.0.0.1)

| Service | URL |
|---|---|
| radar-api / dashboard | http://localhost:8000 |
| n8n | http://localhost:5678 |
| Mailpit | http://localhost:8025 |
| Postgres | localhost:5432 |
| Ollama (profile `local-llm`) | http://localhost:11435 |
