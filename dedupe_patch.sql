ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS event_key TEXT;

-- Backfill existing rows:
-- Prefer Splunk _cd when present, otherwise a deterministic md5 fallback
UPDATE raw_events
SET event_key = COALESCE(
  raw_json->>'_cd',
  md5(
    COALESCE(raw_text,'') || '|' ||
    COALESCE(sourcetype,'') || '|' ||
    COALESCE(source,'') || '|' ||
    COALESCE(host,'') || '|' ||
    COALESCE(event_time::text,'')
  )
)
WHERE event_key IS NULL;

-- Make sure it's always present going forward
ALTER TABLE raw_events ALTER COLUMN event_key SET NOT NULL;

-- Enforce uniqueness
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_raw_events_event_key'
  ) THEN
    ALTER TABLE raw_events ADD CONSTRAINT uq_raw_events_event_key UNIQUE (event_key);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_raw_events_event_key ON raw_events(event_key);
