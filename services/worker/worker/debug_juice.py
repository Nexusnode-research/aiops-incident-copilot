
import os
import time
import psycopg2
import sys
import json

# DB connection params
DB_NAME = os.environ.get("POSTGRES_DB", "aiops")
DB_USER = os.environ.get("POSTGRES_USER", "aiops")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "aiops")
DB_HOST = os.environ.get("POSTGRES_HOST", "postgres")
DB_PORT = os.environ.get("POSTGRES_PORT", "5432")

DSN = f"dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} host={DB_HOST} port={DB_PORT}"

def deep_get(d, keys, default=None):
    if not isinstance(d, dict):
        return default
    k = keys[0]
    if len(keys) == 1:
        return d.get(k, default)
    return deep_get(d.get(k, {}), keys[1:], default)

def run():
    print("Connecting...")
    conn = psycopg2.connect(DSN)
    cur = conn.cursor()
    cur.execute("SELECT raw_json FROM raw_events WHERE sourcetype='juiceshop:app' LIMIT 1;")
    row = cur.fetchone()
    if not row:
        print("No events found")
        return
    
    raw_json = row[0]
    print(f"Top keys: {list(raw_json.keys())}")
    
    if "_raw" in raw_json:
        print(f"_raw type: {type(raw_json['_raw'])}")
        val = raw_json["_raw"]
        # print first 100 chars
        print(f"_raw start: {str(val)[:100]}")
        
        inner = {}
        if isinstance(val, str):
            try:
                inner = json.loads(val)
                print("Parsed _raw successfully")
                print(f"Inner keys: {list(inner.keys())}")
                if "path" in inner:
                    print(f"FOUND path in inner: {inner['path']}")
                elif "req" in inner:
                     print(f"FOUND req in inner: {inner['req']}")
                else:
                    print("path not found in inner")
            except Exception as e:
                print(f"Failed to parse _raw: {e}")
        else:
            print("_raw is not a string")
            
    else:
        print("_raw not in top keys")

    conn.close()

if __name__ == "__main__":
    run()
