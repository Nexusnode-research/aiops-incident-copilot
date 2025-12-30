
import os
import time
import psycopg2
from psycopg2.extras import DictCursor, execute_values

# --- CONFIG ---

def _env(name, default=None):
    v = os.getenv(name)
    return v if v not in (None, "") else default

def normalize_db_url(url):
    if url.startswith("postgresql+psycopg2://"):
        return "postgresql://" + url.split("postgresql+psycopg2://", 1)[1]
    return url

def get_connection():
    db_url = normalize_db_url(os.environ["DATABASE_URL"])
    return psycopg2.connect(db_url)

# --- FEATURE LOGIC ---

def rollup_features(lookback_minutes=15, bin_size_sec=60):
    """
    Aggregates events into time bins and upserts into features_timeseries.
    Idempotent: Re-calculates the last N minutes to handle late arrival.
    """
    
    # Time Window
    # We aggregate by bin_start (truncated to minute)
    
    conn = get_connection()
    try:
        with conn, conn.cursor(cursor_factory=DictCursor) as cur:
            
            # features to compute
            # 1. Auth Failures (Host)
            # 2. Auth Failures (User)
            # 3. Wazuh Alerts (Host)
            # 4. JuiceShop Errors (Endpoint/Path)
            # 5. Src IP Fail Contributions (Secondary Key)
            
            queries = []
            
            # --- 1. Auth Failures (Host) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    'wazuh' as vendor,
                    'auth_fail_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    '-' as secondary_type,
                    '-' as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND rule_id = '4625'
                GROUP BY 1, 5
            """)

            # --- 1b. Auth Success (Host) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    'wazuh' as vendor,
                    'auth_success_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    '-' as secondary_type,
                    '-' as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND rule_id = '4624'
                GROUP BY 1, 5
            """)

            # --- 2. Auth Failures (User) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    'wazuh' as vendor,
                    'auth_fail_count' as feature_name,
                    'user' as entity_type,
                    COALESCE(username, 'unknown') as entity_id,
                    '-' as secondary_type,
                    '-' as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND rule_id = '4625'
                  AND username IS NOT NULL
                GROUP BY 1, 5
            """)
            
            # --- 3. Top Src IP by Auth Failures (Drill-down) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    'wazuh' as vendor,
                    'src_ip_fail_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    'src_ip' as secondary_type,
                    COALESCE(src_ip::text, 'unknown') as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND rule_id = '4625'
                  AND src_ip IS NOT NULL
                GROUP BY 1, 5, 7
            """)

            # --- 4. Wazuh Alerts (Severity > 0) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    'wazuh' as vendor,
                    'wazuh_alert_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    '-' as secondary_type,
                    '-' as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND vendor = 'wazuh'
                GROUP BY 1, 5
            """)
            
            # --- 5. JuiceShop Error Rate (HTTP >= 400 OR App Error) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    'juiceshop' as vendor,
                    'juiceshop_error_count' as feature_name,
                    'endpoint' as entity_type,
                    COALESCE(http_path, 'unknown') as entity_id,
                    '-' as secondary_type,
                    '-' as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND vendor = 'juiceshop'
                  AND (http_status >= 400 OR event_kind = 'alert')
                GROUP BY 1, 5
            """)

            # --- 8. Bad Event Count (Unified Badness) ---
            # Severity >= 5 OR HTTP >= 400 OR Suspicious Signature
            suspicious_sigs = [
                'ET TROJAN', 'ET MALWARE', 'ET POLICY', 'ET INFO External IP', 
                'Wazuh: Critical', 'Auth Failure'
            ]
            # Construct robust SQL condition for suspicious sigs
            sig_condition = " OR ".join([f"signature ILIKE '%%{s}%%'" for s in suspicious_sigs])
            
            queries.append(f"""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    string_agg(distinct vendor, ',') as vendor,
                    'bad_event_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    '-' as secondary_type,
                    '-' as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND (
                    COALESCE(severity, 0) >= 5 OR
                    COALESCE(http_status, 0) >= 400 OR
                    {sig_condition}
                  )
                GROUP BY 1, 5
            """)

            # --- 9. Zenarmor Allowed Count (Separated Noise) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    string_agg(distinct vendor, ',') as vendor,
                    'zenarmor_allowed_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    '-' as secondary_type,
                    '-' as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND vendor = 'opnsense' 
                  AND (signature ILIKE '%%allowed%%' OR signature ILIKE '%%zenarmor:allowed%%')
                GROUP BY 1, 5
            """)

            # --- 6. Signature Counts (Per Host) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    string_agg(distinct vendor, ',') as vendor,
                    'signature_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    'signature' as secondary_type,
                    COALESCE(signature, 'unknown') as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND signature IS NOT NULL
                GROUP BY 1, 5, 7
            """)

            # --- 7. Top Src IP Counts (Per Host) ---
            queries.append("""
                SELECT 
                    date_trunc('minute', event_time) as bin_start,
                    string_agg(distinct vendor, ',') as vendor,
                    'src_ip_count' as feature_name,
                    'host' as entity_type,
                    COALESCE(host, 'unknown') as entity_id,
                    'src_ip' as secondary_type,
                    COALESCE(src_ip::text, 'unknown') as secondary_id,
                    count(*) as value,
                    count(*) as n_events
                FROM normalized_events
                WHERE event_time > NOW() - INTERVAL '%s minutes'
                  AND src_ip IS NOT NULL
                GROUP BY 1, 5, 7
            """)
            
            total_upserted = 0
            
            for q in queries:
                formatted_q = q % (lookback_minutes,)
                # Debug: Peek at feature name in query
                if "feature_name" in formatted_q:
                    import re
                    m_feat = re.search(r"'([\w_]+)' as feature_name", formatted_q)
                    feature_name = m_feat.group(1) if m_feat else 'unknown'
                    print(f"Processing feature: {feature_name}")
                    
                cur.execute(formatted_q)
                rows = cur.fetchall()
                
                if not rows: continue
                
                # Prepare UPSERT
                insert_rows = []
                for r in rows:
                    insert_rows.append((
                        r['bin_start'],
                        bin_size_sec,
                        r['vendor'],
                        r['feature_name'],
                        r['entity_type'],
                        r['entity_id'],
                        r['secondary_type'],
                        r['secondary_id'],
                        r["value"],
                        r["n_events"]
                    ))
                
                sql = """
                    INSERT INTO features_timeseries (
                        bin_start, bin_size_sec, vendor, feature_name,
                        entity_type, entity_id, secondary_type, secondary_id,
                        value, n_events
                    ) VALUES %s
                    ON CONFLICT (bin_start, bin_size_sec, feature_name, entity_type, entity_id, secondary_id)
                    DO UPDATE SET
                        value = EXCLUDED.value,
                        n_events = EXCLUDED.n_events,
                        created_at = NOW()
                """
                
                execute_values(cur, sql, insert_rows)
                total_upserted += len(insert_rows)
                
            print(f"[features] upserted {total_upserted} rows (lookback={lookback_minutes}m)")
            
            # --- Update Entity Stats ---
            # Lightweight upsert of "seen" entities
            cur.execute("""
                INSERT INTO entity_stats (entity_type, entity_id, first_seen, last_seen, event_count, last_updated)
                SELECT 
                    entity_type, 
                    entity_id, 
                    min(bin_start) as first, 
                    max(bin_start) as last, 
                    sum(n_events) as count,
                    NOW()
                FROM features_timeseries
                WHERE created_at >= NOW() - INTERVAL '5 minutes'
                GROUP BY 1, 2
                ON CONFLICT (entity_type, entity_id) DO UPDATE SET
                    last_seen = GREATEST(entity_stats.last_seen, EXCLUDED.last_seen),
                    event_count = entity_stats.event_count + EXCLUDED.event_count,
                    last_updated = NOW()
            """)
            
            # --- Enriched Entity Stats (Top Signature) ---
            # Update top signature for entities seen recently
            # This is expensive, so we only do it for active entities
            # --- Enriched Entity Stats (Top Signature) ---
            # Filter noise, return Top 10 as JSON [{"sig": "...", "count": N}, ...]
            cur.execute("""
                UPDATE entity_stats
                SET top_signatures = subquery.sigs
                FROM (
                    SELECT 
                        entity_type, entity_id, 
                        jsonb_agg(
                            jsonb_build_object('sig', secondary_id, 'count', total_val)
                            ORDER BY total_val DESC
                        ) as sigs
                    FROM (
                        SELECT 
                            entity_type, entity_id, secondary_id, sum(value) as total_val
                        FROM features_timeseries
                        WHERE created_at >= NOW() - INTERVAL '60 minutes'
                          AND feature_name = 'signature_count'
                          AND secondary_id NOT ILIKE '%%allowed%%'
                          AND secondary_id NOT ILIKE '%%zenarmor:allowed%%'
                          AND secondary_id NOT ILIKE '%%ICMP ping%%'
                        GROUP BY 1, 2, 3
                        ORDER BY 4 DESC
                    ) as ranked
                    -- Postgres doesn't easily support LIMIT inside GROUP BY without lateral join or window func
                    -- But we can just aggregation everything and slice heavily in app layer, or use a window func here
                    -- Simplest: just agg fully, list is usually small per entity if filtered. 
                    -- Or strictly Top 10 via CTE? Let's assume filtered list is manageable. 
                    GROUP BY 1, 2
                ) as subquery
                WHERE entity_stats.entity_type = subquery.entity_type
                  AND entity_stats.entity_id = subquery.entity_id;
            """)
            
            # --- Enriched Entity Stats (Unique Src IPs) ---
            cur.execute("""
                UPDATE entity_stats
                SET unique_src_ips = subquery.distinct_ips
                FROM (
                    SELECT 
                        entity_type, entity_id, 
                        count(DISTINCT secondary_id) as distinct_ips
                    FROM features_timeseries 
                    WHERE feature_name = 'src_ip_count'
                    GROUP BY 1, 2
                ) as subquery
                WHERE entity_stats.entity_type = subquery.entity_type
                  AND entity_stats.entity_id = subquery.entity_id;
            """)

            print(f"[features] updated entity_stats")
            
    except Exception as e:
        print(f"[features] error: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=int, default=60, help="Lookback minutes")
    args = parser.parse_args()
    
    rollup_features(lookback_minutes=args.minutes)
