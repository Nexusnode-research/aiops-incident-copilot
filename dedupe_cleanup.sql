-- Ensure all rows have event_key
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

-- Remove duplicates (keep one)
DELETE FROM raw_events a USING raw_events b
WHERE a.ctid < b.ctid AND a.event_key = b.event_key;

-- Now add constraint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_raw_events_event_key'
  ) THEN
    ALTER TABLE raw_events ADD CONSTRAINT uq_raw_events_event_key UNIQUE (event_key);
  END IF;
END $$;
