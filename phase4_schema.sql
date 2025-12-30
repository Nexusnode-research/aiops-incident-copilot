
-- Phase 4 Schema: Incidents & Correlation

-- 1. TRACKING ON SIGNALS
-- Add processed tracking to signal_events to prevent re-correlation
ALTER TABLE signal_events ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE signal_events ADD COLUMN IF NOT EXISTS incident_id INTEGER DEFAULT NULL;

-- Ensure indexes for performance
CREATE INDEX IF NOT EXISTS idx_signals_processed ON signal_events(processed_at) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_signals_entity_time ON signal_events(entity_type, entity_id, event_time);
CREATE INDEX IF NOT EXISTS idx_signals_dedupe_key ON signal_events(dedupe_key); -- Should be unique already

-- 2. INCIDENTS TABLE
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW', -- NEW, ACTIVE, CLOSED
    severity INTEGER NOT NULL DEFAULT 1,
    score DOUBLE PRECISION DEFAULT 0.0,
    
    -- Root Entity (The main victim or actor)
    root_entity_type TEXT NOT NULL,
    root_entity_id TEXT NOT NULL,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_update_time TIMESTAMPTZ DEFAULT NOW(),
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ DEFAULT NOW(),
    
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_root ON incidents(root_entity_type, root_entity_id);
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(last_update_time);

-- 3. INCIDENT EVIDENCE (Mapping)
CREATE TABLE IF NOT EXISTS incident_evidence (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    signal_id INTEGER NOT NULL REFERENCES signal_events(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ DEFAULT NOW(),
    
    PRIMARY KEY (incident_id, signal_id) -- Duplicate Prevention
);

CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_signal ON incident_evidence(signal_id);
