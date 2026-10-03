-- Phase 1: advisories and enrichment data.

-- One row per advisory revision. WID advisories are updated often (D-007), so
-- the key is (advisory_id, version) and old revisions are kept for diffing.
CREATE TABLE radar.advisories (
    advisory_id          text        NOT NULL,          -- e.g. WID-SEC-W-2026-0085
    version              integer     NOT NULL,          -- document.tracking.version
    is_latest            boolean     NOT NULL,
    title                text        NOT NULL,
    severity_text        text,                          -- niedrig | mittel | hoch | kritisch
    tlp                  text        NOT NULL,          -- only WHITE / CLEAR are stored
    initial_release_date timestamptz NOT NULL,
    current_release_date timestamptz NOT NULL,
    revision_summary     text,                          -- summary of the latest revision
    attack_summary       text,                          -- note "Angriff": the one-sentence German summary
    product_description  text,                          -- note "Produktbeschreibung"
    source_url           text        NOT NULL,          -- the CSAF file
    portal_url           text,                          -- human-readable WID page
    "references"         jsonb       NOT NULL,          -- [{category, summary, url}]
    raw                  jsonb       NOT NULL,          -- the full document, for audit and re-parsing
    first_seen_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (advisory_id, version)
);
-- At most one latest revision per advisory.
CREATE UNIQUE INDEX advisories_latest ON radar.advisories (advisory_id) WHERE is_latest;

-- Every product node of the advisory's product tree.
CREATE TABLE radar.advisory_products (
    advisory_id   text    NOT NULL,
    version       integer NOT NULL,
    product_id    text    NOT NULL,   -- BSI's id; fixed versions end in "-fixed"
    vendor        text    NOT NULL,
    product_name  text    NOT NULL,
    node_category text    NOT NULL,   -- product_name | product_version | product_version_range
    version_text  text    NOT NULL,   -- BSI free text, e.g. "<7.2.12"; '' when the node has no version
    full_name     text    NOT NULL,   -- e.g. "Fortinet FortiOS <7.2.12"
    cpe           text,
    is_fixed_node boolean NOT NULL,   -- product_id ends in "-fixed" (D-006)
    PRIMARY KEY (advisory_id, version, product_id),
    FOREIGN KEY (advisory_id, version) REFERENCES radar.advisories ON DELETE CASCADE
);
CREATE INDEX advisory_products_vendor ON radar.advisory_products (lower(vendor));

-- One row per entry of vulnerabilities[]. Some real entries have no CVE, so the
-- position in the list is part of the key and cve may be NULL.
CREATE TABLE radar.advisory_vulnerabilities (
    advisory_id    text    NOT NULL,
    version        integer NOT NULL,
    position       integer NOT NULL,
    cve            text,
    known_affected text[]  NOT NULL,  -- product_ids
    last_affected  text[]  NOT NULL,  -- product_ids
    PRIMARY KEY (advisory_id, version, position),
    FOREIGN KEY (advisory_id, version) REFERENCES radar.advisories ON DELETE CASCADE
);
CREATE INDEX advisory_vulnerabilities_cve ON radar.advisory_vulnerabilities (cve);

-- CISA Known Exploited Vulnerabilities. Replaced completely on every ingest.
CREATE TABLE radar.kev (
    cve               text PRIMARY KEY,
    vendor_project    text NOT NULL,
    product           text NOT NULL,
    vulnerability_name text NOT NULL,
    date_added        date NOT NULL,
    due_date          date,
    ransomware_use    text,           -- "Known" | "Unknown"
    catalog_version   text NOT NULL
);

-- FIRST EPSS. The only EPSS source (D-004).
CREATE TABLE radar.epss (
    cve        text PRIMARY KEY,
    score      numeric(10, 9) NOT NULL,  -- probability 0..1
    percentile numeric(10, 9) NOT NULL,
    score_date date           NOT NULL,
    fetched_at timestamptz    NOT NULL DEFAULT now()
);

-- CVSS scores. The version is stored with every score (D-003).
CREATE TABLE radar.cvss (
    cve        text PRIMARY KEY,
    score      numeric(3, 1),            -- NULL = looked up, but the source has no score
    version    text,                     -- "3.1" | "4.0" | ...
    vector     text,
    source     text        NOT NULL,     -- 'euvd'
    source_id  text,                     -- e.g. EUVD-2026-2223
    fetched_at timestamptz NOT NULL DEFAULT now()
);

-- One row per ingest run: what was pulled and what it changed.
CREATE TABLE radar.ingest_runs (
    run_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    mode        text        NOT NULL,    -- live | offline
    snapshot    text        NOT NULL,    -- snapshot folder used or written
    stats       jsonb
);
