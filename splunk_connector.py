import os, json, argparse
import requests
from requests.auth import HTTPBasicAuth
import psycopg2
from psycopg2.extras import Json, execute_values
from datetime import datetime, timezone

def _env(name, default=None):
    v = os.getenv(name)
    return v if v not in (None, "") else default

def normalize_db_url(url: str) -> str:
    # Your .env uses SQLAlchemy style: postgresql+psycopg2://...
    # psycopg2 expects: postgresql://...
    if url.startswith("postgresql+psycopg2://"):
        return "postgresql://" + url.split("postgresql+psycopg2://", 1)[1]
    return url

def parse_splunk_time(v):
    if v is None:
        return None
    s = str(v).strip()

    # epoch seconds
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except Exception:
        pass

    # "2025-12-18 14:31:16.615 UTC" or without millis
    if s.endswith("UTC"):
        s = s[:-3].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass

    # last resort: store null if unknown
    return None

def fetch_splunk_events(minutes: int, limit: int):
    scheme = _env("SPLUNK_SCHEME", "https")
    host   = os.environ["SPLUNK_HOST"]
    port   = _env("SPLUNK_MGMT_PORT", "8089")
    verify = (_env("SPLUNK_VERIFY_SSL", "false").lower() == "true")

    auth = HTTPBasicAuth(os.environ["SPLUNK_USERNAME"], os.environ["SPLUNK_PASSWORD"])
    url  = f"{scheme}://{host}:{port}/services/search/jobs/export?output_mode=json"

    default_search = (
        f"search earliest=-{minutes}m "
        f"(index=wazuh OR index=network) "
        f"| head {limit}"
    )
    search = _env("SPLUNK_SEARCH", default_search)

    r = requests.post(url, data={"search": search}, auth=auth, verify=verify, timeout=120)
    r.raise_for_status()

    events = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        obj = json.loads(line)
        res = obj.get("result")
        if not res:
            continue
        events.append(res)

    return search, events

def insert_events(events):
    db_url = normalize_db_url(os.environ["DATABASE_URL"])
    conn = psycopg2.connect(db_url)
    try:
        with conn, conn.cursor() as cur:
            rows = []
            for ev in events:
                # common fields
                et = parse_splunk_time(ev.get("_time"))
                sourcetype = ev.get("sourcetype")
                source     = ev.get("source")
                host       = ev.get("host")

                # wazuh-specific fields (may or may not exist)
                agent_name = ev.get("agent.name") or ev.get("agent_name")
                rule_id    = ev.get("rule.id") or ev.get("rule_id")

                raw_text = ev.get("_raw")
                if raw_text is None:
                    raw_text = json.dumps(ev, ensure_ascii=False)

                rows.append((
                    et, sourcetype, source, host, agent_name, rule_id,
                    Json(ev), raw_text
                ))

            if not rows:
                return 0

            sql = """
            INSERT INTO raw_events
            (event_time, sourcetype, source, host, agent_name, rule_id, raw_json, raw_text)
            VALUES %s
            """
            execute_values(cur, sql, rows, page_size=500)
            return len(rows)
    finally:
        conn.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=int(_env("LOOKBACK_MINUTES", "15")))
    ap.add_argument("--limit", type=int, default=500)
    args = ap.parse_args()

    search, events = fetch_splunk_events(args.minutes, args.limit)
    print(f"[splunk] search = {search}")
    print(f"[splunk] fetched = {len(events)} events")

    inserted = insert_events(events)
    print(f"[db] inserted = {inserted} rows into raw_events")

if __name__ == "__main__":
    main()
