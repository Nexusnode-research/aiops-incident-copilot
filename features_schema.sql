-- features_schema.sql
-- Phase 2: Feature Layer (Time-Series)

CREATE TABLE IF NOT EXISTS features_timeseries (
    bin_start       TIMESTAMPTZ NOT NULL,
    bin_size_sec    INT NOT NULL,          -- 60 (1m), 300 (5m)
    vendor          TEXT NOT NULL,
    feature_name    TEXT NOT NULL,         -- 'auth_fail_count', 'juiceshop_error_count'
    entity_type     TEXT NOT NULL,         -- 'host', 'user', 'src_ip', 'endpoint'
    entity_id       TEXT NOT NULL,
    secondary_type  TEXT,                  -- 'src_ip' (for drill-down contexts)
    secondary_id    TEXT,
    value           DOUBLE PRECISION NOT NULL,
    n_events        INT DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    
    -- Idempotency Key: Ensure unique feature value per bin/entity
    UNIQUE (bin_start, bin_size_sec, feature_name, entity_type, entity_id, secondary_id)
);

-- Indexes for efficient querying by time range and entity
CREATE INDEX IF NOT EXISTS idx_features_time ON features_timeseries(bin_start);
CREATE INDEX IF NOT EXISTS idx_features_entity ON features_timeseries(entity_type, entity_id);
-- Index for rapid Upsert checks
CREATE INDEX IF NOT EXISTS idx_features_upsert ON features_timeseries(bin_start, feature_name, entity_id);
