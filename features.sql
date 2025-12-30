-- Phase 2: Feature Store Tables

-- 0. Optimization Indexes (Run once)
CREATE INDEX IF NOT EXISTS idx_norm_event_time   ON normalized_events(event_time);
CREATE INDEX IF NOT EXISTS idx_norm_host_time    ON normalized_events(host, event_time);
CREATE INDEX IF NOT EXISTS idx_norm_user_time    ON normalized_events(username, event_time);
CREATE INDEX IF NOT EXISTS idx_norm_sig_time     ON normalized_events(signature, event_time);
CREATE INDEX IF NOT EXISTS idx_norm_rule_time    ON normalized_events(rule_id, event_time);
CREATE INDEX IF NOT EXISTS idx_norm_srcip_time   ON normalized_events(src_ip, event_time);
CREATE INDEX IF NOT EXISTS idx_norm_path_time    ON normalized_events(http_path, event_time);

-- 1. features_timeseries (Generic metrics store)
CREATE TABLE IF NOT EXISTS features_timeseries (
  bucket_start         timestamptz NOT NULL,
  bucket_size_seconds  integer     NOT NULL,     -- 60 or 300
  entity_type          text        NOT NULL,     -- host | user | signature | rule_id | endpoint
  entity_id            text        NOT NULL,
  metric               text        NOT NULL,     -- event_count, auth_fail_count, etc
  value                double precision,
  meta                 jsonb,
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (bucket_start, bucket_size_seconds, entity_type, entity_id, metric)
);

CREATE INDEX IF NOT EXISTS idx_ft_metric_time
  ON features_timeseries(metric, bucket_start);

CREATE INDEX IF NOT EXISTS idx_ft_entity
  ON features_timeseries(entity_type, entity_id);

-- 2. entity_stats (Rolling "who/what is hot")
CREATE TABLE IF NOT EXISTS entity_stats (
  entity_type     text        NOT NULL,
  entity_id       text        NOT NULL,
  first_seen      timestamptz,
  last_seen       timestamptz,
  total_events    bigint,
  unique_src_ips  bigint,
  unique_users    bigint,
  top_signatures  jsonb,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (entity_type, entity_id)
);
