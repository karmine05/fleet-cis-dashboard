-- Fleet CIS Compliance Dashboard Schema (PostgreSQL 16)

-- Enable useful extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Teams
CREATE TABLE IF NOT EXISTS fleet_teams (
    team_id BIGINT PRIMARY KEY,
    team_name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ
);

-- Hosts
CREATE TABLE IF NOT EXISTS fleet_hosts (
    host_id BIGINT PRIMARY KEY,
    hostname TEXT NOT NULL,
    uuid TEXT,
    platform TEXT,
    platform_version TEXT,
    osquery_version TEXT,
    team_id BIGINT, -- Can be NULL for global
    team_name TEXT,
    online_status TEXT,
    last_seen TIMESTAMPTZ,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (team_id) REFERENCES fleet_teams(team_id) ON DELETE SET NULL
);

-- CIS Policies (enriched from fleet_policies tags / cis_safeguard_ids)
CREATE TABLE IF NOT EXISTS cis_policies (
    policy_id BIGINT PRIMARY KEY,
    policy_name TEXT NOT NULL,
    cis_control TEXT,              -- benchmark section number (legacy, from name)
    description TEXT,
    resolution TEXT,
    query TEXT,
    category TEXT,
    severity TEXT,
    platform TEXT,
    cis_safeguard_ids TEXT[] DEFAULT '{}',  -- e.g. {CIS8.4,CIS4.1} from tags
    benchmark TEXT,                -- e.g. ubuntu24.04, win11, macosTahoe
    control_slug TEXT,             -- tags.control
    cis_category TEXT,             -- tags.cis_category
    cis_subcategory TEXT,
    framework TEXT,                -- e.g. CISv8.1
    level TEXT,
    tags JSONB DEFAULT '{}'::jsonb,
    catalog_matched BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_policies_safeguard ON cis_policies USING GIN (cis_safeguard_ids);
CREATE INDEX IF NOT EXISTS idx_policies_benchmark ON cis_policies(benchmark);

-- cis_policies.team_id: which Fleet team a policy belongs to (NULL = global).
-- The stale-policy cleanup prunes per-scope, not all-or-nothing: a policy is only
-- deleted when the scope that owns it (global or a specific team) was fetched
-- successfully this sync. Without this column the cleanup cannot tell a stale
-- team policy from a stale global one, so a single failing team fetch forced it
-- to skip the WHOLE catalog — and deleted policies lingered forever. See
-- sync_fleet_data.compute_stale_policy_ids().
--
-- CREATE TABLE IF NOT EXISTS is a no-op on an existing database, so the column
-- and its FK are added idempotently here. New rows are NULL until the next sync
-- upserts team_id, which is safe: NULL rows are only pruned when the global fetch
-- succeeded AND the teams-list fetch succeeded (see the cleanup guard).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'cis_policies'
          AND column_name = 'team_id'
    ) THEN
        ALTER TABLE cis_policies ADD COLUMN team_id BIGINT;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'cis_policies'::regclass
          AND conname = 'cis_policies_team_fk'
    ) THEN
        ALTER TABLE cis_policies
            ADD CONSTRAINT cis_policies_team_fk
            FOREIGN KEY (team_id) REFERENCES fleet_teams(team_id) ON DELETE SET NULL;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_policies_team ON cis_policies(team_id);

-- Policy Results (Current State)
-- Optimized for dashboard queries ("show me current status")
CREATE TABLE IF NOT EXISTS policy_results (
    policy_id BIGINT,
    host_id BIGINT,
    status TEXT CHECK(status IN ('pass', 'fail', 'error')),
    checked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (policy_id, host_id),
    FOREIGN KEY (policy_id) REFERENCES cis_policies(policy_id),
    FOREIGN KEY (host_id) REFERENCES fleet_hosts(host_id) ON DELETE CASCADE
);

-- Policy Results History (Partitioned by Month)
-- Stores historical changes for trend analysis/retention
CREATE TABLE IF NOT EXISTS policy_results_history (
    history_id BIGSERIAL,
    policy_id BIGINT,
    host_id BIGINT,
    status TEXT,
    checked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (history_id, checked_at) -- Partition key must be part of PK
) PARTITION BY RANGE (checked_at);

-- Monthly partitions are deliberately NOT declared here.
-- schema.sql is executed on every sync by init_db(), so a hardcoded list of months
-- silently rots: once the calendar moves past the last listed month every row lands in
-- the DEFAULT partition, and rows sitting in DEFAULT then BLOCK a later ATTACH of a real
-- partition covering that range ("updated partition constraint for default partition
-- would be violated"). Ownership instead:
--   * ensure_history_partitions() in sync_fleet_data.py creates the current month plus
--     the next two, idempotently, once per sync before any history INSERT. When it
--     creates a month it also relocates any rows already stranded in DEFAULT for that
--     month, inside the same transaction, so no separate backfill step is needed.
--   * run_retention() ages out whatever remains in DEFAULT past the retention window.
-- Monthly partitions created by older revisions of this file stay attached; they are
-- empty and harmless, and ensure_history_partitions() skips names that already exist.
--
-- The DEFAULT partition is kept on purpose: it is the safety net for timestamps outside
-- the pre-created window, so a history INSERT can never fail outright.
CREATE TABLE IF NOT EXISTS policy_results_history_def PARTITION OF policy_results_history DEFAULT;

-- Compliance Snapshots (Daily aggregates)
CREATE TABLE IF NOT EXISTS compliance_snapshots (
    snapshot_id BIGSERIAL PRIMARY KEY,
    snapshot_date DATE NOT NULL,
    team_id BIGINT,
    compliance_score REAL,
    critical_failures INTEGER,
    passing_hosts INTEGER,
    FOREIGN KEY (team_id) REFERENCES fleet_teams(team_id)
);

-- One snapshot row per (snapshot_date, team_id), with team_id NULL meaning the global
-- row. CREATE TABLE IF NOT EXISTS above does nothing on an already-provisioned database,
-- so the uniqueness guarantee has to be applied separately -- and because schema.sql runs
-- on every sync it must be a cheap no-op once satisfied.
-- NULLS NOT DISTINCT (PG15+) is what makes this work: under plain UNIQUE semantics every
-- global row (team_id IS NULL) is distinct from every other, so duplicate global rows
-- would still be accepted.
DO $$
DECLARE
    removed INTEGER;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'compliance_snapshots'::regclass
          AND conname = 'compliance_snapshots_date_team_uniq'
    ) OR EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = current_schema()
          AND tablename = 'compliance_snapshots'
          AND indexname = 'compliance_snapshots_date_team_uniq'
    ) THEN
        RETURN;
    END IF;

    -- A database provisioned before this constraint existed can already hold duplicate
    -- (snapshot_date, team_id) rows, and ADD CONSTRAINT would fail on them forever.
    -- Snapshots are re-derivable daily aggregates, so keeping the highest snapshot_id
    -- per key (the most recently written aggregate) is the correct repair.
    DELETE FROM compliance_snapshots c
    USING (
        SELECT snapshot_date, team_id, MAX(snapshot_id) AS keep_id
        FROM compliance_snapshots
        GROUP BY snapshot_date, team_id
        HAVING COUNT(*) > 1
    ) d
    WHERE c.snapshot_date = d.snapshot_date
      AND c.team_id IS NOT DISTINCT FROM d.team_id
      AND c.snapshot_id <> d.keep_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    IF removed > 0 THEN
        -- RAISE ... USING MESSAGE keeps this file free of '%' placeholders: schema.sql is
        -- handed to psycopg2 as one string, and a caller that ever passes bind params
        -- would make psycopg2 try to interpolate a bare '%' and fail.
        RAISE NOTICE USING MESSAGE =
            'compliance_snapshots: dropped ' || removed
            || ' duplicate (snapshot_date, team_id) row(s)';
    END IF;

    BEGIN
        ALTER TABLE compliance_snapshots
            ADD CONSTRAINT compliance_snapshots_date_team_uniq
            UNIQUE NULLS NOT DISTINCT (snapshot_date, team_id);
    EXCEPTION WHEN others THEN
        -- Never let schema bootstrap (and therefore the whole sync) die here. Two
        -- concurrent syncs racing on the same DDL is the expected cause; the loser just
        -- sees the constraint already present on its next run.
        RAISE WARNING USING MESSAGE =
            'could not add compliance_snapshots_date_team_uniq: ' || SQLERRM;
    END;
END $$;

-- Labels
CREATE TABLE IF NOT EXISTS fleet_labels (
    label_id BIGINT PRIMARY KEY,
    label_name TEXT NOT NULL,
    label_type TEXT,
    description TEXT
);

-- Host Labels
CREATE TABLE IF NOT EXISTS host_labels (
    host_id BIGINT NOT NULL,
    label_id BIGINT NOT NULL,
    PRIMARY KEY (host_id, label_id),
    FOREIGN KEY (host_id) REFERENCES fleet_hosts(host_id) ON DELETE CASCADE,
    FOREIGN KEY (label_id) REFERENCES fleet_labels(label_id) ON DELETE CASCADE
);

-- Configuration Settings
CREATE TABLE IF NOT EXISTS config_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sync Metadata
CREATE TABLE IF NOT EXISTS sync_metadata (
    sync_id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status TEXT CHECK(status IN ('running','success','failed')) DEFAULT 'running',
    hosts_changed INTEGER DEFAULT 0,
    policies_changed INTEGER DEFAULT 0,
    results_changed INTEGER DEFAULT 0,
    duration_ms INTEGER,
    error_message TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_hosts_team ON fleet_hosts(team_id);
CREATE INDEX IF NOT EXISTS idx_hosts_updated ON fleet_hosts(updated_at);
CREATE INDEX IF NOT EXISTS idx_results_host ON policy_results(host_id);
CREATE INDEX IF NOT EXISTS idx_results_policy ON policy_results(policy_id);
CREATE INDEX IF NOT EXISTS idx_results_status ON policy_results(status);
CREATE INDEX IF NOT EXISTS idx_host_labels_host ON host_labels(host_id);
CREATE INDEX IF NOT EXISTS idx_history_checked ON policy_results_history(checked_at);

-- Trend queries have the shape "per-day per-policy status aggregate over a lookback
-- window": WHERE checked_at >= now() - interval '<N> days' GROUP BY <day>, policy_id.
-- checked_at leads because the window is the only selective predicate (there is no
-- policy_id filter), so each surviving partition is served by a single range scan; with
-- policy_id leading, PG16 has no index skip-scan and the same query degrades to a full
-- index scan. policy_id trails so the range scan already emits rows ordered by
-- (checked_at, policy_id) and the grouping needs no extra sort.
-- Indexes on a partitioned parent are partitioned indexes in PG16: this propagates to
-- existing partitions and to every partition created or attached later, which is what
-- makes runtime partition creation safe.
CREATE INDEX IF NOT EXISTS idx_history_checked_policy ON policy_results_history(checked_at, policy_id);
