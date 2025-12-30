import os
import json
import glob
import time
import psycopg2
from psycopg2.extras import Json, execute_values
from datetime import datetime, timezone, timedelta
from splunk_connector import make_event_key, normalize_db_url, parse_splunk_time

def main():
    print("[seed] Starting demo data seeding...")
    
    # DB Connection
    db_env = os.environ.get("DATABASE_URL")
    if not db_env:
        print("[seed] DATABASE_URL not set. Exiting.")
        return
        
    db_url = normalize_db_url(db_env)
    
    sample_dir = "/app/samples"
    if not os.path.exists(sample_dir):
        print(f"[seed] Warning: {sample_dir} not found. Skipping seed.")
        return

    # Load all json files
    files = glob.glob(os.path.join(sample_dir, "*.json"))
    if not files:
        print(f"[seed] No JSON files found in {sample_dir}.")
        return

    total_inserted = 0
    conn = None
    
    try:
        conn = psycopg2.connect(db_url)
        with conn, conn.cursor() as cur:
            for fpath in files:
                print(f"[seed] Processing {fpath}...")
                with open(fpath, 'r', encoding='utf-8-sig') as f:
                    # Multi-Format Parser
                    events = []
                    try:
                        # 1. Try passing whole file (JSON Array or Single Object)
                        content = json.load(f)
                        
                        if isinstance(content, list):
                            events = content
                        elif isinstance(content, dict):
                            # Handle Splunk wrapper {"result": ...} or {"results": [...]}
                            if "results" in content and isinstance(content["results"], list):
                                events = content["results"]
                            elif "result" in content and isinstance(content["result"], dict):
                                events = [content["result"]]
                            else:
                                events = [content]
                        else:
                            print(f"[seed] Unknown content type in {fpath}, skipping.")
                            continue
                            
                    except json.JSONDecodeError:
                        # 2. Fallback: JSON Lines (NDJSON)
                        f.seek(0)
                        events = []
                        for line_num, line in enumerate(f):
                            line = line.strip()
                            if not line: continue
                            try:
                                obj = json.loads(line)
                                # Handle Splunk wrapper per line
                                if isinstance(obj, dict) and "result" in obj:
                                    events.append(obj["result"])
                                else:
                                    events.append(obj)
                            except Exception as ex:
                                print(f"[seed] Failed to parse line {line_num+1} in {fpath}: {ex}")
                                continue
                    
                    rows = []
                    # Establish "now" for this batch
                    now = datetime.now(timezone.utc)
                    
                    for ev in events:
                        # Shift timestamp to "now" to trigger detections
                        # We overwrite _time and keep the rest
                        ev["_time"] = now.timestamp()
                        
                        # Generate Key (using splunk_connector logic)
                        # Depends on _time, so it changes per run -> Fresh data
                        key = make_event_key(ev)
                        
                        # Extract fields
                        et = now
                        sourcetype = ev.get("sourcetype")
                        source = ev.get("source")
                        host = ev.get("host")
                        agent_name = ev.get("agent.name") or ev.get("agent_name")
                        rule_id = ev.get("rule.id") or ev.get("rule_id")
                        raw_text = ev.get("_raw")
                        if raw_text is None:
                            raw_text = json.dumps(ev, ensure_ascii=False)
                            
                        rows.append((
                            key, et, sourcetype, source, host, agent_name, rule_id,
                            Json(ev), raw_text
                        ))
                    
                    if rows:
                        sql = """
                        INSERT INTO raw_events
                        (event_key, event_time, sourcetype, source, host, agent_name, rule_id, raw_json, raw_text)
                        VALUES %s
                        ON CONFLICT (event_key) DO NOTHING
                        """
                        execute_values(cur, sql, rows, page_size=500)
                        total_inserted += cur.rowcount
                        print(f"[seed]   Inserted {cur.rowcount} events from {os.path.basename(fpath)}")
                        
    except Exception as e:
        print(f"[seed] Error during seeding: {e}")
    finally:
        if conn:
            conn.close()
        
    print(f"[seed] Done. Total new events: {total_inserted}")

if __name__ == "__main__":
    main()
