-- 1. RAW EVENTS
CREATE TABLE IF NOT EXISTS raw_events (
    id BIGSERIAL PRIMARY KEY,
    event_key TEXT UNIQUE NOT NULL,
    event_time TIMESTAMPTZ,
    sourcetype TEXT,
    source TEXT,
    host TEXT,
    agent_name TEXT,
    rule_id TEXT,
    raw_json JSONB,
    raw_text TEXT
);

-- 2. NORMALIZED EVENTS
CREATE TABLE IF NOT EXISTS normalized_events (
  id BIGSERIAL PRIMARY KEY,
  raw_id BIGINT REFERENCES raw_events(id) ON DELETE CASCADE,
  
  -- Core Identity
  event_time TIMESTAMPTZ NOT NULL,
  ingest_time TIMESTAMPTZ DEFAULT now(),
  vendor TEXT, -- Added to match normalize.py
  host TEXT,
  source TEXT,
  sourcetype TEXT,
  event_kind TEXT NOT NULL,
  severity INT DEFAULT 0,
  
  -- User / Network
  username TEXT, -- Renamed from user_name match normalize.py
  src_ip INET,
  dest_ip INET,
  src_port INT,
  dest_port INT,

  -- Security Logic
  rule_id TEXT,
  rule_name TEXT,
  signature TEXT,

  -- Web Fields
  http_method TEXT,
  http_path TEXT,
  http_status INT, -- Renamed from status_code to match normalize.py
  user_agent TEXT,

  -- Flex
  extras JSONB,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  UNIQUE(raw_id)
);

CREATE INDEX IF NOT EXISTS idx_norm_time ON normalized_events(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_norm_host ON normalized_events(host);
CREATE INDEX IF NOT EXISTS idx_norm_ip ON normalized_events(src_ip, dest_ip);
CREATE INDEX IF NOT EXISTS idx_norm_kind ON normalized_events(event_kind);

-- 3. FEATURES TIME-SERIES (Matches features.py)
CREATE TABLE IF NOT EXISTS features_timeseries (
    bin_start       TIMESTAMPTZ NOT NULL,
    bin_size_sec    INT NOT NULL,
    vendor          TEXT NOT NULL,
    feature_name    TEXT NOT NULL,
    entity_type     TEXT NOT NULL,
    entity_id       TEXT NOT NULL,
    secondary_type  TEXT,
    secondary_id    TEXT,
    value           DOUBLE PRECISION NOT NULL,
    n_events        INT DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE (bin_start, bin_size_sec, feature_name, entity_type, entity_id, secondary_id)
);

CREATE INDEX IF NOT EXISTS idx_features_time ON features_timeseries(bin_start);
CREATE INDEX IF NOT EXISTS idx_features_entity ON features_timeseries(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_features_upsert ON features_timeseries(bin_start, feature_name, entity_id);

-- 4. ENTITY STATS (Derived from features.py usage)
CREATE TABLE IF NOT EXISTS entity_stats (
  entity_type     text        NOT NULL,
  entity_id       text        NOT NULL,
  
  first_seen      timestamptz,
  last_seen       timestamptz,
  event_count     bigint DEFAULT 0,
  unique_src_ips  bigint DEFAULT 0,
  unique_users    bigint DEFAULT 0,
  top_signatures  jsonb,
  
  last_updated    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (entity_type, entity_id)
);

-- 5. SIGNAL EVENTS
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
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Phase 4 Additions
    processed_at TIMESTAMPTZ DEFAULT NULL,
    incident_id INTEGER DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_signals_time ON signal_events(event_time);
CREATE INDEX IF NOT EXISTS idx_signals_dedupe ON signal_events(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_signals_processed ON signal_events(processed_at) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_signals_entity_time ON signal_events(entity_type, entity_id, event_time);

-- 6. DETECTION CHECKPOINTS
CREATE TABLE IF NOT EXISTS detection_checkpoints (
    job_name TEXT PRIMARY KEY,
    last_run_time TIMESTAMPTZ NOT NULL,
    last_window_end TIMESTAMPTZ NOT NULL
);

-- 7. INCIDENTS
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW',
    severity INTEGER NOT NULL DEFAULT 1,
    score DOUBLE PRECISION DEFAULT 0.0,
    
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

-- 8. INCIDENT EVIDENCE
CREATE TABLE IF NOT EXISTS incident_evidence (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    signal_id INTEGER NOT NULL REFERENCES signal_events(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ DEFAULT NOW(),
    
    PRIMARY KEY (incident_id, signal_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_signal ON incident_evidence(signal_id);
