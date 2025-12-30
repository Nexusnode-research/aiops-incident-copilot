
import os
import time
import psycopg2
import sys
import json
from datetime import datetime, timedelta

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

def build_signals():
    print("[signals] Starting signal generation...")
    conn = get_conn()
    cur = conn.cursor()
    
    start_time = time.time()
    
    # 1. Determine feature_now (latest bucket in features)
    cur.execute("SELECT max(bin_start) FROM features_timeseries WHERE bin_size_sec = 60;")
    row = cur.fetchone()
    feature_now = row[0]
    
    if not feature_now:
        print("[signals] No feature data found. Exiting.")
        return

    print(f"[signals] feature_now is {feature_now}")

    # 2. Spike Detection: Auth Failures (Host)
    # Compare last 1 hour vs baseline (previous 6 hours)
    print("[signals] Detecting Auth Failure Spikes...")
    
    current_window_start = feature_now - timedelta(hours=1)
    baseline_window_start = feature_now - timedelta(hours=7)
    baseline_window_end = feature_now - timedelta(hours=1)
    
    # We look for significant deviations (e.g. current > 3 * baseline_avg + threshold)
    spike_sql = """
    WITH current_window AS (
        SELECT entity_id, sum(value) as current_sum
        FROM features_timeseries
        WHERE feature_name = 'auth_fail_count' 
          AND entity_type = 'host'
          AND bin_size_sec = 60
          AND bin_start > %s
        GROUP BY entity_id
    ),
    baseline_window AS (
        SELECT entity_id, sum(value) as baseline_sum, avg(value) as baseline_avg
        FROM features_timeseries
        WHERE feature_name = 'auth_fail_count'
          AND entity_type = 'host'
          AND bin_size_sec = 60
          AND bin_start > %s
          AND bin_start <= %s
        GROUP BY entity_id
    )
    SELECT 
        c.entity_id, 
        c.current_sum, 
        COALESCE(b.baseline_sum, 0) as baseline_sum, 
        COALESCE(b.baseline_avg, 0) as baseline_avg
    FROM current_window c
    LEFT JOIN baseline_window b ON c.entity_id = b.entity_id
    -- Thresholds: AT LEAST 5 failures, AND > 3x the baseline average + 5
    WHERE c.current_sum >= 5 
      AND c.current_sum > (COALESCE(b.baseline_avg, 0) * 3 + 5)
    """
    
    cur.execute(spike_sql, (current_window_start, baseline_window_start, baseline_window_end))
    spikes = cur.fetchall()
    
    for entity_id, current_sum, baseline_sum, baseline_avg in spikes:
        score = current_sum / (baseline_avg + 0.1)
        evidence = {
            "current_sum": current_sum, 
            "baseline_avg": float(f"{baseline_avg:.2f}"),
            "window": "1h vs 6h"
        }
        
        # Dedupe key: signal_name|entity_type|entity_id|window_end(timestamp)
        # Using feature_now as window_end timestamp
        ts_str = feature_now.strftime('%Y%m%d%H%M%S')
        dedupe_key = f"auth_fail_spike|host|{entity_id}|{ts_str}"
        
        insert_sql = """
        INSERT INTO signal_events (event_time, window_start, window_end, signal_name, entity_type, entity_id, severity, score, dedupe_key, metadata)
        VALUES (%s, %s, %s, 'auth_fail_spike', 'host', %s, 7, %s, %s, %s)
        ON CONFLICT (dedupe_key) DO NOTHING
        """
        run_query(conn, insert_sql, (feature_now, current_window_start, feature_now, entity_id, score, dedupe_key, json.dumps(evidence)))
        print(f"[signals] Generated auth_fail_spike for {entity_id}")

    # 3. Silent Agent Detection
    print("[signals] Detecting Silent Agents...")
    
    lookback_24h = feature_now - timedelta(hours=24)
    lookback_1h = feature_now - timedelta(hours=1)
    
    silent_sql = """
    WITH active_baseline AS (
        SELECT DISTINCT entity_id
        FROM features_timeseries
        WHERE feature_name = 'event_count'
          AND entity_type = 'host'
          AND bin_size_sec = 60
          AND bin_start > %s
          AND bin_start <= %s
    ),
    active_recent AS (
        SELECT DISTINCT entity_id
        FROM features_timeseries
        WHERE feature_name = 'event_count'
          AND entity_type = 'host'
          AND bin_size_sec = 60
          AND bin_start > %s
    )
    SELECT b.entity_id
    FROM active_baseline b
    LEFT JOIN active_recent r ON b.entity_id = r.entity_id
    WHERE r.entity_id IS NULL
    """
    
    cur.execute(silent_sql, (lookback_24h, lookback_1h, lookback_1h))
    silents = cur.fetchall()
    
    for (entity_id,) in silents:
        if entity_id == '(none)': continue
        
        ts_str = feature_now.strftime('%Y%m%d%H%M%S')
        dedupe_key = f"agent_silent|host|{entity_id}|{ts_str}"
        
        insert_sql = """
        INSERT INTO signal_events (event_time, window_start, window_end, signal_name, entity_type, entity_id, severity, score, dedupe_key, metadata)
        VALUES (%s, %s, %s, 'agent_silent', 'host', %s, 3, 10.0, %s, '{}')
        ON CONFLICT (dedupe_key) DO NOTHING
        """
        run_query(conn, insert_sql, (feature_now, lookback_1h, feature_now, entity_id, dedupe_key))
        print(f"[signals] Generated silent agent for {entity_id}")

    # 4. JuiceShop App Error Spike (Fallback since endpoints are missing)
    # Detect if 'error' severity events spiked
    print("[signals] Detecting JuiceShop Error Spikes...")
    
    # We will query features_timeseries for JuiceShop hosts/signatures? 
    # Actually, we don't have 'severity' in features_timeseries directly?
    # Phase 2 implementation didn't aggregate by severity.
    # But we have 'error_rate' for entity_type='endpoint', entity_id='(none)'.
    # Because my normalize failed to extract path but maybe normalization logic put SOMETHING in http_status?
    # Step 762 http_path was empty. http_status?
    
    # Let's try to use the 'error_rate' metric even if entity_id is (none) or empty
    # If entity_id is empty string or (none), we treat it as "Global App".
    
    juice_spike_sql = """
    WITH current_window AS (
        SELECT entity_id, avg(value) as current_rate
        FROM features_timeseries
        WHERE feature_name = 'error_rate' 
          AND entity_type = 'endpoint'
          AND bin_size_sec = 60
          AND bin_start > %s
        GROUP BY entity_id
    ),
    baseline_window AS (
        SELECT entity_id, avg(value) as baseline_rate
        FROM features_timeseries
        WHERE feature_name = 'error_rate' 
          AND entity_type = 'endpoint'
          AND bin_size_sec = 60
          AND bin_start > %s
          AND bin_start <= %s
        GROUP BY entity_id
    )
    SELECT 
        c.entity_id, 
        c.current_rate, 
        COALESCE(b.baseline_rate, 0) as baseline_rate
    FROM current_window c
    LEFT JOIN baseline_window b ON c.entity_id = b.entity_id
    WHERE c.current_rate > 0.05 -- > 5 percent error rate
      AND c.current_rate > (COALESCE(b.baseline_rate, 0) * 2) -- > 2x baseline
    """
    
    cur.execute(juice_spike_sql, (current_window_start, baseline_window_start, baseline_window_end))
    jspikes = cur.fetchall()
    
    for entity_id, current_rate, baseline_rate in jspikes:
        eid = "juiceshop_global" if entity_id in ["", "(none)", None] else entity_id
        score = current_rate / (baseline_rate + 0.01)
        evidence = {
            "current_rate": float(f"{current_rate:.2f}"), 
            "baseline_rate": float(f"{baseline_rate:.2f}"),
            "window": "1h vs 6h"
        }
        
        ts_str = feature_now.strftime('%Y%m%d%H%M%S')
        dedupe_key = f"app_error_spike|application|{eid}|{ts_str}"
        
        insert_sql = """
        INSERT INTO signal_events (event_time, window_start, window_end, signal_name, entity_type, entity_id, severity, score, dedupe_key, metadata)
        VALUES (%s, %s, %s, 'app_error_spike', 'application', %s, 5, %s, %s, %s)
        ON CONFLICT (dedupe_key) DO NOTHING
        """
        run_query(conn, insert_sql, (feature_now, current_window_start, feature_now, eid, score, dedupe_key, json.dumps(evidence)))
        print(f"[signals] Generated app_error_spike for {eid}")


    conn.close()
    print(f"[signals] Done in {time.time() - start_time:.2f}s")

if __name__ == "__main__":
    try:
        build_signals()
    except Exception as e:
        print(f"[signals] Error: {e}")
        sys.exit(1)
