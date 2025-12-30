
import os
import time
import psycopg2
import sys

# DB connection params
DB_NAME = os.environ.get("POSTGRES_DB", "aiops")
DB_USER = os.environ.get("POSTGRES_USER", "aiops")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "aiops")
DB_HOST = os.environ.get("POSTGRES_HOST", "postgres")
DB_PORT = os.environ.get("POSTGRES_PORT", "5432")

DSN = f"dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} host={DB_HOST} port={DB_PORT}"

def get_conn():
    return psycopg2.connect(DSN)

def run_query(conn, sql, params=None):
    with conn.cursor() as cur:
        cur.execute(sql, params or ())
    conn.commit()

def build_features():
    print("[features] Starting feature build...")
    conn = get_conn()
    
    start_time = time.time()
    
    # 2. Backfill rollups for 5-minute bins (bucket = 300s)
    
    # 2.2 Counts per host
    print("[features] Building counts per host...")
    run_query(conn, """
    WITH params AS (SELECT 300::int AS bucket_s),
    base AS (
      SELECT
        to_timestamp(floor(extract(epoch from event_time) / (SELECT bucket_s FROM params)) * (SELECT bucket_s FROM params))::timestamptz AS bucket_start,
        COALESCE(NULLIF(host,''), '(none)') AS host
      FROM normalized_events
    )
    INSERT INTO features_timeseries (bucket_start, bucket_size_seconds, entity_type, entity_id, metric, value, meta)
    SELECT
      bucket_start,
      (SELECT bucket_s FROM params),
      'host',
      host,
      'event_count',
      count(*)::double precision,
      NULL::jsonb
    FROM base
    GROUP BY bucket_start, host
    ON CONFLICT (bucket_start, bucket_size_seconds, entity_type, entity_id, metric)
    DO UPDATE SET value = EXCLUDED.value, updated_at = now();
    """)
    
    # 2.3 Counts per signature
    print("[features] Building counts per signature...")
    run_query(conn, """
    WITH params AS (SELECT 300::int AS bucket_s),
    base AS (
      SELECT
        to_timestamp(floor(extract(epoch from event_time) / (SELECT bucket_s FROM params)) * (SELECT bucket_s FROM params))::timestamptz AS bucket_start,
        NULLIF(signature,'') AS signature,
        sourcetype
      FROM normalized_events
      WHERE signature IS NOT NULL AND signature <> ''
    )
    INSERT INTO features_timeseries (bucket_start, bucket_size_seconds, entity_type, entity_id, metric, value, meta)
    SELECT
      bucket_start,
      (SELECT bucket_s FROM params),
      'signature',
      signature,
      'event_count',
      count(*)::double precision,
      jsonb_build_object('sourcetype', sourcetype)
    FROM base
    GROUP BY bucket_start, signature, sourcetype
    ON CONFLICT (bucket_start, bucket_size_seconds, entity_type, entity_id, metric)
    DO UPDATE SET value = EXCLUDED.value, meta = EXCLUDED.meta, updated_at = now();
    """)
    
    # 2.4 Counts per rule_id (Wazuh)
    print("[features] Building counts per rule_id (Wazuh)...")
    run_query(conn, """
    WITH params AS (SELECT 300::int AS bucket_s),
    base AS (
      SELECT
        to_timestamp(floor(extract(epoch from event_time) / (SELECT bucket_s FROM params)) * (SELECT bucket_s FROM params))::timestamptz AS bucket_start,
        COALESCE(NULLIF(rule_id,''), '(none)') AS rule_id
      FROM normalized_events
      WHERE sourcetype = 'wazuh-alerts'
    )
    INSERT INTO features_timeseries (bucket_start, bucket_size_seconds, entity_type, entity_id, metric, value, meta)
    SELECT
      bucket_start,
      (SELECT bucket_s FROM params),
      'rule_id',
      rule_id,
      'event_count',
      count(*)::double precision,
      NULL::jsonb
    FROM base
    GROUP BY bucket_start, rule_id
    ON CONFLICT (bucket_start, bucket_size_seconds, entity_type, entity_id, metric)
    DO UPDATE SET value = EXCLUDED.value, updated_at = now();
    """)
    
    # 2.5 Auth failure counts (host + user)
    print("[features] Building auth failure counts...")
    run_query(conn, """
    WITH params AS (SELECT 300::int AS bucket_s),
    flagged AS (
      SELECT
        to_timestamp(floor(extract(epoch from event_time) / (SELECT bucket_s FROM params)) * (SELECT bucket_s FROM params))::timestamptz AS bucket_start,
        COALESCE(NULLIF(host,''), '(none)') AS host,
        NULLIF(username,'') AS username,
        CASE
          WHEN sourcetype = 'wazuh-alerts'
           AND signature IS NOT NULL
           AND (
                lower(signature) LIKE '%%failed password%%'
             OR lower(signature) LIKE '%%authentication failed%%'
             OR lower(signature) LIKE '%%invalid user%%'
             OR lower(signature) LIKE '%%logon failure%%'
             OR lower(signature) LIKE '%%login failed%%'
           )
          THEN 1 ELSE 0
        END AS is_auth_fail
      FROM normalized_events
    )
    -- Combined host and user metrics
    INSERT INTO features_timeseries (bucket_start, bucket_size_seconds, entity_type, entity_id, metric, value, meta)
    SELECT
      bucket_start,
      (SELECT bucket_s FROM params),
      'host',
      host,
      'auth_fail_count',
      sum(is_auth_fail)::double precision,
      NULL::jsonb
    FROM flagged
    GROUP BY bucket_start, host
    UNION ALL
    SELECT
      bucket_start,
      (SELECT bucket_s FROM params),
      'user',
      COALESCE(username, '(none)'),
      'auth_fail_count',
      sum(is_auth_fail)::double precision,
      NULL::jsonb
    FROM flagged
    GROUP BY bucket_start, COALESCE(username, '(none)')
    ON CONFLICT (bucket_start, bucket_size_seconds, entity_type, entity_id, metric)
    DO UPDATE SET value = EXCLUDED.value, updated_at = now();
    """)
    
    # 2.6 Top src_ip per host
    print("[features] Building top src_ip per host...")
    run_query(conn, """
    WITH params AS (SELECT 300::int AS bucket_s),
    counts AS (
      SELECT
        to_timestamp(floor(extract(epoch from event_time) / (SELECT bucket_s FROM params)) * (SELECT bucket_s FROM params))::timestamptz AS bucket_start,
        COALESCE(NULLIF(host,''), '(none)') AS host,
        src_ip::text AS src_ip,
        count(*) AS c
      FROM normalized_events
      WHERE src_ip IS NOT NULL
      GROUP BY 1,2,3
    ),
    ranked AS (
      SELECT *,
        row_number() OVER (PARTITION BY bucket_start, host ORDER BY c DESC) AS rn
      FROM counts
    )
    INSERT INTO features_timeseries (bucket_start, bucket_size_seconds, entity_type, entity_id, metric, value, meta)
    SELECT
      bucket_start,
      (SELECT bucket_s FROM params),
      'host',
      host,
      'top_src_ip',
      NULL,
      jsonb_build_object(
        'top', jsonb_agg(jsonb_build_object('src_ip', src_ip, 'count', c) ORDER BY c DESC)
      )
    FROM ranked
    WHERE rn <= 5
    GROUP BY bucket_start, host
    ON CONFLICT (bucket_start, bucket_size_seconds, entity_type, entity_id, metric)
    DO UPDATE SET meta = EXCLUDED.meta, updated_at = now();
    """)
    
    # 2.7 JuiceShop error rate
    print("[features] Building JuiceShop error rates...")
    run_query(conn, """
    WITH params AS (SELECT 300::int AS bucket_s),
    base AS (
      SELECT
        to_timestamp(floor(extract(epoch from event_time) / (SELECT bucket_s FROM params)) * (SELECT bucket_s FROM params))::timestamptz AS bucket_start,
        COALESCE(NULLIF(http_path,''), '(none)') AS endpoint,
        http_status
      FROM normalized_events
      WHERE sourcetype = 'juiceshop:app'
    )
    INSERT INTO features_timeseries (bucket_start, bucket_size_seconds, entity_type, entity_id, metric, value, meta)
    SELECT
      bucket_start,
      (SELECT bucket_s FROM params),
      'endpoint',
      endpoint,
      'error_rate',
      (sum(CASE WHEN http_status >= 400 THEN 1 ELSE 0 END)::double precision / NULLIF(count(*),0)),
      jsonb_build_object(
        'total', count(*),
        'errors', sum(CASE WHEN http_status >= 400 THEN 1 ELSE 0 END)
      )
    FROM base
    GROUP BY bucket_start, endpoint
    ON CONFLICT (bucket_start, bucket_size_seconds, entity_type, entity_id, metric)
    DO UPDATE SET value = EXCLUDED.value, meta = EXCLUDED.meta, updated_at = now();
    """)
    
    # 3. Entity stats
    print("[features] Building entity stats...")
    run_query(conn, """
    INSERT INTO entity_stats (entity_type, entity_id, first_seen, last_seen, total_events, unique_src_ips, unique_users, top_signatures)
    SELECT
      'host' AS entity_type,
      COALESCE(NULLIF(host,''), '(none)') AS entity_id,
      min(event_time) AS first_seen,
      max(event_time) AS last_seen,
      count(*) AS total_events,
      count(DISTINCT src_ip) FILTER (WHERE src_ip IS NOT NULL) AS unique_src_ips,
      count(DISTINCT username) FILTER (WHERE username IS NOT NULL AND username <> '') AS unique_users,
      NULL::jsonb AS top_signatures
    FROM normalized_events
    GROUP BY 1,2
    ON CONFLICT (entity_type, entity_id)
    DO UPDATE SET
      first_seen = LEAST(entity_stats.first_seen, EXCLUDED.first_seen),
      last_seen  = GREATEST(entity_stats.last_seen, EXCLUDED.last_seen),
      total_events = EXCLUDED.total_events,
      unique_src_ips = EXCLUDED.unique_src_ips,
      unique_users = EXCLUDED.unique_users,
      updated_at = now();
    """)
    
    conn.close()
    print(f"[features] Done in {time.time() - start_time:.2f}s")

if __name__ == "__main__":
    try:
        build_features()
    except Exception as e:
        print(f"[features] Error: {e}")
        sys.exit(1)
