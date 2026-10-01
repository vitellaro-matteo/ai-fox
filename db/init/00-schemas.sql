-- Runs once, when the Postgres volume is created empty.
-- One database, two schemas: n8n owns `n8n`, our service owns `radar`.
-- The tables in `radar` are created by the service's own migrations
-- (radar/db/migrations), not here, so they can evolve without a volume reset.

CREATE SCHEMA IF NOT EXISTS n8n;
CREATE SCHEMA IF NOT EXISTS radar;
