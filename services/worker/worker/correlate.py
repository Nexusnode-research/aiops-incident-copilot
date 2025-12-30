
import os
import time
import psycopg2
from psycopg2.extras import DictCursor
from datetime import datetime, timedelta, timezone

# --- CONFIG ---
INCIDENT_WINDOW_MINUTES = 30 # Match signals to incidents updated within X min

def get_connection():
    db_url = os.environ["DATABASE_URL"]
    if db_url.startswith("postgresql+psycopg2://"):
        db_url = "postgresql://" + db_url.split("postgresql+psycopg2://", 1)[1]
    return psycopg2.connect(db_url)

def correlate_signals():
    conn = get_connection()
    try:
        # 1. Fetch Unprocessed Signals
        # Limit to 500 to avoid memory blast
        sql_fetch = """
            SELECT id, signal_name, entity_type, entity_id, severity, score, event_time, window_start, window_end
            FROM signal_events
            WHERE processed_at IS NULL
            ORDER BY window_end ASC
            LIMIT 500
        """
        
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(sql_fetch)
            signals = cur.fetchall()
            
        if not signals:
            print("[correlate] No new signals to process.")
            return

        print(f"[correlate] Processing {len(signals)} signals...")
        
        # 2. Process each signal
        processed_ids = []
        
        for sig in signals:
            # Logic:
            # Find an ACTIVE/NEW incident for this Entity that was updated recently.
            # If found -> Attach.
            # If not found -> Create NEW Incident.
            
            sig_id = sig["id"]
            entity_type = sig["entity_type"]
            entity_id = sig["entity_id"]
            timestamp = sig["window_end"] # Use the end of the signal window as the event time
            
            with conn.cursor(cursor_factory=DictCursor) as cur:
                # Find matching incident
                # Matches: Same Root Entity AND Updated recently
                cur.execute("""
                    SELECT id FROM incidents
                    WHERE root_entity_type = %s 
                      AND root_entity_id = %s
                      AND status IN ('NEW', 'ACTIVE')
                      AND last_update_time >= %s - INTERVAL '%s minutes' -- Alive recently
                      AND start_time >= %s - INTERVAL '4 hours' -- No infinite incidents
                    ORDER BY last_update_time DESC
                    LIMIT 1
                """, (entity_type, entity_id, timestamp, INCIDENT_WINDOW_MINUTES, timestamp))
                
                row = cur.fetchone()
                
                if row:
                    # Attach to existing
                    incident_id = row['id']
                    # Link Evidence (Idempotent via ON CONFLICT)
                    cur.execute("""
                        INSERT INTO incident_evidence (incident_id, signal_id, added_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (incident_id, signal_id) DO NOTHING
                    """, (incident_id, sig_id))
                    
                    # Update Incident Stats
                    cur.execute("""
                        UPDATE incidents
                        SET 
                            last_update_time = GREATEST(last_update_time, %s),
                            end_time = GREATEST(end_time, %s),
                            severity = GREATEST(severity, %s),
                            score = score + LEAST(%s, 50)
                        WHERE id = %s
                    """, (timestamp, timestamp, sig["severity"], sig["score"], incident_id))
                    
                else:
                    # Create New Incident
                    title = f"{sig['signal_name']} on {entity_id}"
                    cur.execute("""
                        INSERT INTO incidents (
                            title, status, severity, score, 
                            root_entity_type, root_entity_id, 
                            start_time, end_time, last_update_time, created_at
                        ) VALUES (%s, 'NEW', %s, %s, %s, %s, %s, %s, %s, NOW())
                        RETURNING id
                    """, (
                        title, sig["severity"], sig["score"], 
                        entity_type, entity_id, 
                        sig["window_start"], sig["window_end"], timestamp
                    ))
                    incident_id = cur.fetchone()[0]
                    
                    # Link Evidence
                    cur.execute("""
                        INSERT INTO incident_evidence (incident_id, signal_id, added_at)
                        VALUES (%s, %s, NOW())
                    """, (incident_id, sig_id))
            
            processed_ids.append(sig_id)

        # 3. Mark Signals as Processed
        if processed_ids:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE signal_events
                    SET processed_at = NOW()
                    WHERE id = ANY(%s)
                """, (processed_ids,))
            conn.commit()
            print(f"[correlate] Correlated {len(processed_ids)} signals.")
            
    except Exception as e:
        print(f"[correlate] Error: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    correlate_signals()
