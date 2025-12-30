-- Phase 3: Signal Layer

-- 1. signals (Alerts/Anomalies store)
CREATE TABLE IF NOT EXISTS signals (
  id bigserial PRIMARY KEY,
  signal_time timestamptz NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,

  signal_type text NOT NULL,         -- e.g. spike_zscore, agent_silent, drift_new_signature
  entity_type text NOT NULL,         -- host/user/signature/rule/endpoint/sourcetype
  entity_id text NOT NULL,           -- e.g. "172.16.58.50" or "admin" or "/api/Users/login"
  metric text NOT NULL,              -- e.g. auth_fail_count, event_count, error_rate
  score double precision NOT NULL,   -- anomaly strength

  severity text NOT NULL DEFAULT 'info',  -- info/low/med/high/critical
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,

  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_signals_time ON signals(signal_time DESC);
CREATE INDEX IF NOT EXISTS idx_signals_entity ON signals(entity_type, entity_id, signal_time DESC);
CREATE INDEX IF NOT EXISTS idx_signals_type ON signals(signal_type, signal_time DESC);
