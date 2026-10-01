"""HTTP entry point of radar-api. n8n and the dashboard talk to the service only through here."""

import os

import psycopg
from fastapi import FastAPI

app = FastAPI(title="Schwachstellen-Radar API", version="0.1.0")


@app.get("/health")
def health() -> dict:
    # Liveness only: answers even if the database is down, so Docker can tell
    # "process crashed" apart from "dependency unavailable".
    return {"status": "ok"}


@app.get("/health/db")
def health_db() -> dict:
    # Readiness: checks that Postgres is reachable and our schema exists.
    with psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=3) as conn:
        row = conn.execute(
            "SELECT count(*) FROM information_schema.schemata WHERE schema_name = 'radar'"
        ).fetchone()
    return {"status": "ok" if row and row[0] == 1 else "schema_missing"}
