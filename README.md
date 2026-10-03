# Schwachstellen-Radar

**Vom Sicherheitshinweis zum freigegebenen Patch-Ticket.**

Ein IT-Dienstleister betreut die IT von Dutzenden Mittelstandskunden. Täglich
erscheinen neue Sicherheitshinweise, beim BSI allein rund 16 neue und rund 30
aktualisierte pro Tag (Juli–September 2026). Heute prüft ein Analyst jeden Hinweis von Hand: Welcher Kunde
setzt das Produkt ein? Wie dringend ist es? Was ist zu tun?

Der Schwachstellen-Radar übernimmt die Routine:

1. **Erfassen:** Er holt jeden Morgen die aktuellen BSI-Hinweise (CERT-Bund WID) und
   reichert sie mit CISA KEV (aktiv ausgenutzt?), FIRST EPSS
   (Ausnutzungswahrscheinlichkeit) und ENISA EUVD (CVSS-Bewertung) an.
2. **Abgleichen:** Er vergleicht betroffene Produkte und Versionen mit dem Inventar
   jedes Kunden.
3. **Priorisieren:** Die Priorität folgt festen, nachvollziehbaren Regeln. Jede
   Einstufung ist begründet.
4. **Entwerfen:** Er erstellt ein Techniker-Ticket und eine Kundeninformation auf
   Deutsch, aus festen Vorlagen und geprüften Daten.
5. **Freigeben:** Ein Analyst prüft und gibt mit einem Klick frei. Nichts geht ohne
   Freigabe an Kunden.
6. **Nachweisen:** Jede Entscheidung wird protokolliert, als Nachweis für das
   Schwachstellenmanagement nach NIS2 (§ 30 Abs. 2 Nr. 5 BSIG).

**Die Rolle der KI:** Sie übersetzt unscharfe Inventareinträge („Forti 60F FW 7.2.5“)
in Struktur und schreibt eine kurze, verständliche Zusammenfassung. Sie entscheidet **nicht** über die Priorität, handelt
auf keinem System und versendet nichts. *Die KI übersetzt, der Code entscheidet, der
Mensch gibt frei.*

> Status: Phase 1 (Erfassung). Es entstehen keine laufenden Kosten: Das Sprachmodell
> läuft lokal. Die Kundendaten sind fiktiv, die Sicherheitshinweise
> sind echt.

---

## Technical setup

### Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine with Compose v2 (Linux)
- Python 3.10+ on the host (only for the task runner; everything else runs in containers)
- Optional: `mingw32-make` (Windows) or `make` (macOS/Linux)
- Optional: [Ollama](https://ollama.com) on the host for the local-model option
- Optional: [uv](https://docs.astral.sh/uv/) for running tests on the host

### First start

```bash
cp .env.example .env        # then set POSTGRES_PASSWORD and N8N_ENCRYPTION_KEY
```

Every task works in two equivalent ways:

| Task | With make (Windows: `mingw32-make`) | Without make |
|---|---|---|
| Start the stack | `mingw32-make up` | `python scripts/tasks.py up` |
| Stop the stack | `mingw32-make down` | `python scripts/tasks.py down` |
| Follow the logs | `mingw32-make logs` | `python scripts/tasks.py logs` |
| Run the tests | `mingw32-make test` | `python scripts/tasks.py test` |
| List all tasks | `mingw32-make help` | `python scripts/tasks.py` |

Pulling advisories:

| Task | With make | Without make |
|---|---|---|
| Daily pull (last 3 days) | `mingw32-make ingest` | `python scripts/tasks.py ingest` |
| First fill (last 90 days, about 30 min) | `mingw32-make ingest ARGS="--days 90"` | `python scripts/tasks.py ingest --days 90` |
| Replay a snapshot, no network | `mingw32-make ingest ARGS="--offline data/snapshots/2026-10-01"` | `python scripts/tasks.py ingest --offline data/snapshots/2026-10-01` |

Later phases add `seed`, `demo`, `demo-offline`, `eval`, `stats`, `reset`.
Until then they print which phase will add them.

Then open:

| Service | URL |
|---|---|
| radar-api / dashboard | http://localhost:8000 (health check: `/health`, `/health/db`) |
| n8n | http://localhost:5678 (create the owner account on first visit) |
| Mailpit | http://localhost:8025 |

### LLM providers (both free)

| Provider | Role | Setting |
|---|---|---|
| Ollama (local) | **Default.** Demo, and anything that could hold real customer data | `LLM_PROVIDER=ollama` |
| Groq free tier | Option B: faster development and eval runs, synthetic data only | `LLM_PROVIDER=groq` + `GROQ_API_KEY` |

Both run the same open-weight model (`gpt-oss-20b`) with the same prompts and the same
output validation. Without a `GROQ_API_KEY` everything uses Ollama; that is not an
error. The live demo never calls Groq. See D-015 to D-018 in
[docs/DECISIONS.md](docs/DECISIONS.md).

```bash
ollama pull gpt-oss:20b     # 14 GB download; see D-016 about memory on a 16 GB machine
```

### Local model via the host Ollama

The containers reach the Ollama running on your host at
`http://host.docker.internal:11434`:

- **Windows/macOS (Docker Desktop):** `host.docker.internal` works out of the box.
- **Linux:** `docker-compose.yml` maps it with `extra_hosts: host-gateway`. Ollama on the
  host must also listen on more than localhost: start it with `OLLAMA_HOST=0.0.0.0`.

Check it from inside a container:

```bash
docker compose exec radar-api python -c "import urllib.request;print(urllib.request.urlopen('http://host.docker.internal:11434/api/version').read())"
```

No Ollama on the host? Use the container instead:

```bash
docker compose --profile local-llm up -d
# and set OLLAMA_BASE_URL=http://ollama:11434 in .env
```

### Project documents

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, data flow, trust boundaries
- [docs/DECISIONS.md](docs/DECISIONS.md): every non-trivial decision and its trade-off
- [docs/LEARNING.md](docs/LEARNING.md): explanations and likely interview questions
- [data/samples/README.md](data/samples/README.md): where each real data sample comes from

### Data sources and attribution

BSI CERT-Bund WID (TLP:WHITE), CISA Known Exploited Vulnerabilities Catalog, FIRST
EPSS (https://www.first.org/epss), ENISA EUVD. EUVD data is fetched at runtime and
cached locally, but never committed (see D-008).
