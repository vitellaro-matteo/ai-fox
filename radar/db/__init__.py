"""Database access: one connection helper and a minimal migration runner.

No ORM (D-014): every query in this project is plain SQL that can be read
and explained as it is.
"""

import os
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def connect() -> psycopg.Connection:
    return psycopg.connect(os.environ["DATABASE_URL"])


def migrate(conn: psycopg.Connection) -> list[str]:
    """Applies every migration file that has not run yet, in file-name order.

    Returns the names of the files applied by this call.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS radar.schema_migrations ("
        " name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
    )
    done = {row[0] for row in conn.execute("SELECT name FROM radar.schema_migrations")}
    applied = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if path.name in done:
            continue
        # One transaction per file: a broken migration leaves no half-built tables.
        with conn.transaction():
            conn.execute(path.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO radar.schema_migrations (name) VALUES (%s)", (path.name,))
        applied.append(path.name)
    conn.commit()
    return applied
