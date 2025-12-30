
import os
import time
import json
import hashlib
import psycopg2
from datetime import datetime, timedelta, timezone
from psycopg2.extras import DictCursor, execute_values

# --- CONFIG ---
THRESHOLD_BAD_EVENT = 50  # Simple Hard Threshold for MVP
LOOKBACK_MINUTES = 60     # How far back to check for unprocessed windows
WINDOW_SIZE_MINUTES = 5   # Size of detection window

def get_connection():
    db_url = os.environ["DATABASE_URL"]
    if db_url.startswith("postgresql+psycopg2://"):
        db_url = "postgresql://" + db_url.split("postgresql+psycopg2://", 1)[1]
    return psycopg2.connect(db_url)

def get_checkpoint(conn, job_name):
    with conn.cursor() as cur:
        cur.execute("SELECT last_window_end FROM detection_checkpoints WHERE job_name = %s", (job_name,))
        row = cur.fetchone()
        if row:
            return row[0]
    return None

def update_checkpoint(conn, job_name, window_end):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO detection_checkpoints (job_name, last_run_time, last_window_end)
            VALUES (%s, NOW(), %s)
            ON CONFLICT (job_name) DO UPDATE SET
                last_run_time = NOW(),
                last_window_end = GREATEST(detection_checkpoints.last_window_end, EXCLUDED.last_window_end)
        """, (job_name, window_end))
    conn.commit()

def generate_dedupe_key(signal_name, entity_type, entity_id, window_end_iso):
    raw = f"{signal_name}|{entity_type}|{entity_id}|{window_end_iso}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

def detect_spikes(conn, start_time, end_time):
    """
    Detects spikes in bad_event_count within the given range.
    """
    signals = []
    
    # Query aggregated bad_event_count per entity 
    # (Assuming we want to alert on Host/IP spikes)
    # We sum up 1m buckets into the window
    sql = """
        SELECT 
            entity_type, 
            entity_id, 
            SUM(value) as total_badness,
            MIN(bin_start) as win_start,
            MAX(bin_start) as win_end
        FROM features_timeseries
        WHERE feature_name = 'bad_event_count'
          AND bin_start >= %s 
          AND bin_start < %s
        GROUP BY entity_type, entity_id
        HAVING SUM(value) > %s
    """
    
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (start_time, end_time, THRESHOLD_BAD_EVENT))
        rows = cur.fetchall()
        
        for r in rows:
            val = r["total_badness"]
            # Generate Alert
            sig = {
                "signal_name": "Spike in Bad Events",
                "entity_type": r["entity_type"],
                "entity_id": r["entity_id"],
                "severity": 7, # Critical
                "score": float(val),
                "window_start": r["win_start"],
                "window_end": r["win_end"] or end_time, # Fallback
                "metadata": {
                    "feature": "bad_event_count",
                    "threshold": THRESHOLD_BAD_EVENT,
                    "value": val
                }
            }
            signals.append(sig)
            
    return signals

def detect_raw_alerts(conn, start_time, end_time):
    """
    Promotes High Severity events from normalized_events to Signals.
    Filter: Severity >= 7 OR (Opnsense IDS) OR (Wazuh >= 10)
    """
    signals = []
    
    sql = """
        SELECT 
            event_time, vendor, event_kind, 
            rule_id, signature, severity,
            host, src_ip, dest_ip
        FROM normalized_events
        WHERE event_time >= %s AND event_time < %s
          AND (
            severity >= 7
            OR (vendor = 'opnsense' AND event_kind = 'ids')
          )
    """
    
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (start_time, end_time))
        rows = cur.fetchall()
        
        for r in rows:
            # Determine Entity (Host or Src IP)
            entity_type = "host"
            entity_id = r["host"]
            
            if r["vendor"] == "opnsense" and r["src_ip"]:
                entity_type = "ip"
                entity_id = r["src_ip"]
            
            if not entity_id or entity_id == "unknown":
                continue

            sig_name = r["signature"] or f"{r['vendor']} Alert"
            
            signals.append({
                "signal_name": sig_name,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "severity": r["severity"] if r["severity"] > 0 else 4,
                "score": 10.0, # Base score for explicit alert
                "window_start": r["event_time"],
                "window_end": r["event_time"], # point-in-time
                "metadata": {
                    "rule_id": r["rule_id"],
                    "vendor": r["vendor"],
                    "src_ip": r["src_ip"],
                    "dest_ip": r["dest_ip"]
                }
            })
            
    return signals

def run_detections():
    conn = get_connection()
    try:
        # Determine Window
        # Default: Process last WINDOW_SIZE_MINUTES if checkpont is missing
        # If checkpoint exists, process from checkpoint up to NOW - 1 min (latency buffer)
        
        # Use strict UTC-aware time
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        
        checkpoint = get_checkpoint(conn, "detections_main")
        
        if not checkpoint:
            # First run: start from X minutes ago
            start_time = now - timedelta(minutes=LOOKBACK_MINUTES)
        else:
            start_time = checkpoint
            
        # Ensure we don't process future/incomplete buckets
        # End time = now (exclusive)
        end_time = now
        
        if start_time >= end_time:
            print("[detections] Up to date (Last check: {})".format(start_time))
            return

        print("[detections] Running from {} to {}".format(start_time, end_time))

        # Run Logic
        signals = detect_spikes(conn, start_time, end_time)
        signals.extend(detect_raw_alerts(conn, start_time, end_time))
        
        if signals:
            print("[detections] Found {} signals".format(len(signals)))
            
            # Insert
            with conn.cursor() as cur:
                ins_rows = []
                for s in signals:
                    # Dedupe Key
                    w_end_iso = s["window_end"].isoformat() if hasattr(s["window_end"], "isoformat") else str(s["window_end"])
                    dk = generate_dedupe_key(s["signal_name"], s["entity_type"], s["entity_id"], w_end_iso)
                    
                    ins_rows.append((
                        s["window_start"],
                        s["window_end"],
                        s["signal_name"],
                        s["entity_type"],
                        s["entity_id"],
                        s["severity"],
                        s["score"],
                        dk,
                        json.dumps(s["metadata"])
                    ))
                
                sql = """
                    INSERT INTO signal_events (
                        window_start, window_end, signal_name, 
                        entity_type, entity_id, severity, score, dedupe_key, metadata
                    ) VALUES %s
                    ON CONFLICT (dedupe_key) DO NOTHING
                """
                execute_values(cur, sql, ins_rows)
                conn.commit()
        else:
            print("[detections] No signals found")

        # Update Checkpoint
        update_checkpoint(conn, "detections_main", end_time)
        
    finally:
        conn.close()

if __name__ == "__main__":
    run_detections()
