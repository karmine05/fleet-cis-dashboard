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

-- CIS Policies
CREATE TABLE IF NOT EXISTS cis_policies (
    policy_id BIGINT PRIMARY KEY,
    policy_name TEXT NOT NULL,
    cis_control TEXT,
    description TEXT,
    resolution TEXT,
    query TEXT,
    category TEXT,
    severity TEXT,
    platform TEXT
);

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

-- Partitions for 2025-2026 (Monthly)
CREATE TABLE IF NOT EXISTS policy_results_history_def PARTITION OF policy_results_history DEFAULT;
CREATE TABLE IF NOT EXISTS policy_results_history_y2025m01 PARTITION OF policy_results_history FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE IF NOT EXISTS policy_results_history_y2025m02 PARTITION OF policy_results_history FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE IF NOT EXISTS policy_results_history_y2025m03 PARTITION OF policy_results_history FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE IF NOT EXISTS policy_results_history_y2025m04 PARTITION OF policy_results_history FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE IF NOT EXISTS policy_results_history_y2026m01 PARTITION OF policy_results_history FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

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
