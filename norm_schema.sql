CREATE TABLE IF NOT EXISTS normalized_events (
  id BIGSERIAL PRIMARY KEY,
  -- raw_id is nullable for direct inserts, but usually links to raw_events
  raw_id BIGINT REFERENCES raw_events(id) ON DELETE CASCADE,
  
  -- Core Identity
  event_time TIMESTAMPTZ NOT NULL,
  ingest_time TIMESTAMPTZ DEFAULT now(),
  host TEXT NOT NULL,
  source TEXT,
  sourcetype TEXT,
  event_kind TEXT NOT NULL,  -- auth, process, network, web, ids, agent_health
  severity INT,              -- 0-10 scale
  
  -- User / Network (Nullable)
  user_name TEXT,            -- Renamed from 'user' to avoid keyword issues, or use "user" with quotes
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
  status_code INT,
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
