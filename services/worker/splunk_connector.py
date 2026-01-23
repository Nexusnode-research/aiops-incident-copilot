import os, json, argparse
import requests
from requests.auth import HTTPBasicAuth
import psycopg2
from psycopg2.extras import Json, execute_values
from datetime import datetime, timezone, timedelta
import hashlib

_TZ_ABBREV = {
    "UTC": timezone.utc,
    "CAT": timezone(timedelta(hours=2)),   # Central Africa Time (UTC+2)
    "SAST": timezone(timedelta(hours=2)),  # South Africa Standard Time (UTC+2)
}

def make_event_key(ev: dict) -> str:
    # Best key from Splunk (stable + unique)
    cd = ev.get("_cd")
    if cd:
        return f"splunk:{cd}"

    # Fallback: deterministic hash of core fields
    base = "|".join([
        str(ev.get("_time", "")),
        str(ev.get("sourcetype", "")),
        str(ev.get("source", "")),
        str(ev.get("host", "")),
        str(ev.get("_raw", "")),
    ])
    h = hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()
    return f"hash:{h}"

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

    # ISO 8601 (with offset or Z)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        pass

    # "YYYY-mm-dd HH:MM:SS(.mmm) TZ" (e.g. UTC/CAT/SAST)
    parts = s.split()
    if len(parts) >= 3 and parts[-1] in _TZ_ABBREV:
        tz = _TZ_ABBREV[parts[-1]]
        base = " ".join(parts[:-1])
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(base, fmt).replace(tzinfo=tz).astimezone(timezone.utc)
            except Exception:
                pass

    # fallback: treat as UTC if it matches common formats
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
        f"("
        f"  (index=wazuh (sourcetype=wazuh-alerts OR sourcetype=juiceshop:app)) OR "
        f"  (index=main (sourcetype=suricata OR sourcetype=zenarmor)) OR "
        f"  (sourcetype=XmlWinEventLog OR sourcetype=WinEventLog OR sourcetype=syslog OR sourcetype=opnsense)"
        f") "
        f"| fields * "
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
                    make_event_key(ev),
                    et, sourcetype, source, host, agent_name, rule_id,
                    Json(ev), raw_text
                ))

            if not rows:
                return 0

            sql = """
            INSERT INTO raw_events
            (event_key, event_time, sourcetype, source, host, agent_name, rule_id, raw_json, raw_text)
            VALUES %s
            ON CONFLICT (event_key) DO NOTHING
            """
            execute_values(cur, sql, rows, page_size=500)
            return cur.rowcount
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
