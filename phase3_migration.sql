
-- 1. Severity Migration
-- Ensure clean data (Pre-verified count=0, but good for idempotency)
UPDATE normalized_events SET severity = '0' WHERE severity !~ '^\d+$' OR severity IS NULL;

-- Convert TEXT to INTEGER
ALTER TABLE normalized_events ALTER COLUMN severity TYPE INTEGER USING severity::integer;
ALTER TABLE normalized_events ALTER COLUMN severity SET DEFAULT 0;
ALTER TABLE normalized_events ADD CONSTRAINT severity_range CHECK (severity BETWEEN 0 AND 15);

-- 2. Signal Events Table
CREATE TABLE IF NOT EXISTS signal_events (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMPTZ DEFAULT NOW(),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    signal_name TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    severity INTEGER NOT NULL,
    score DOUBLE PRECISION,
    dedupe_key TEXT UNIQUE NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signals_time ON signal_events(event_time);
CREATE INDEX IF NOT EXISTS idx_signals_dedupe ON signal_events(dedupe_key);

-- 3. Checkpoint Table for Detections
CREATE TABLE IF NOT EXISTS detection_checkpoints (
    job_name TEXT PRIMARY KEY,
    last_run_time TIMESTAMPTZ NOT NULL,
    last_window_end TIMESTAMPTZ NOT NULL
);
