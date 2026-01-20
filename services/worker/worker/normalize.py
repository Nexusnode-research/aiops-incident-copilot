
import os
import json
import time
import argparse
import psycopg2
import re
from psycopg2.extras import DictCursor, execute_values

# --- CONFIG & UTILS ---

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

def safe_int(v):
    try:
        return int(v) if v is not None else None
    except:
        return None

# --- EXTRACTION LOGIC ---

# Regex Patterns
RE_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
RE_NGINX = re.compile(r'^(\S+) \S+ \S+ \[.*?\] "(.*?) (.*?) .*?" (\d+)')
RE_WIN_SRC_IP = re.compile(r"SourceIp:\s*([\d\.]+)|Source Address:\s*([\d\.]+)")
RE_WIN_DEST_IP = re.compile(r"DestinationIp:\s*([\d\.]+)|Destination Address:\s*([\d\.]+)")
RE_WIN_USER = re.compile(r"User:\s*([^\r\n]+)|Account Name:\s*([^\r\n]+)")
# Suricata: Look for [Classification: ...] or [Priority: ...]
# Example: suricata 4011 - [meta sequenceId="..."] [Classification: ...]
RE_SURICATA_SYSLOG = re.compile(r"suricata|Classification:")
RE_ZENARMOR_SYSLOG = re.compile(r"action (\w+) ([^\s]+)")

def extract_winevent_message(msg):
    """Parses text body of Windows Events (Sysmon/Security)"""
    data = {}
    if not msg: return data

    m_src = RE_WIN_SRC_IP.search(msg)
    if m_src:
        data["src_ip"] = m_src.group(1) or m_src.group(2)
    
    m_dest = RE_WIN_DEST_IP.search(msg)
    if m_dest:
        data["dest_ip"] = m_dest.group(1) or m_dest.group(2)
        
    # XML Extraction (Priority) - Iterate to find non-hyphen
    # Sometimes the first TargetUserName is just "-", so we check all occurrences.
    for m_xml in re.finditer(r"TargetUserName.*?>(.*?)<", msg):
        candidate = m_xml.group(1).strip()
        if candidate and candidate != "-":
            data["username"] = candidate
            break
    
    # Text Fallback
    if not data.get("username"):
        m_user = RE_WIN_USER.search(msg)
        if m_user:
            data["username"] = (m_user.group(1) or m_user.group(2)).strip()

    m_source = re.search(r"SourceName=([^\r\n]+)", msg)
    if m_source:
        data["win_source"] = m_source.group(1).strip()
    
    # Extract EventCode for rule_id fallback
    m_code = re.search(r"EventCode=(\d+)", msg)
    if m_code:
        data["rule_id"] = m_code.group(1)

    return data

def extract_nginx(raw):
    """Parses Nginx Access Log line"""
    if not raw: return {}
    m = RE_NGINX.search(raw)
    if m:
        return {
            "src_ip": m.group(1),
            "http_method": m.group(2),
            "http_path": m.group(3),
            "http_status": safe_int(m.group(4)),
            "event_kind": "web"
        }
    return {}

def classify_vendor(row, sourcetype, source):
    """Determines vendor and event_kind based on metadata"""
    st = (sourcetype or "").lower()
    src = (source or "").lower()
    
    # WinEventLog / XmlWinEventLog -> windows (unless sourcetype says wazuh-alerts)
    if "wazuh-alerts" in st:
         return "wazuh", "alert"

    if "wazuh" in st or "wineventlog" in st:
        if "sysmon" in src or "sysmon" in st:
            return "sysmon", "process" 
        return "windows", "event"
    
    if "opnsense" in st or "suricata" in st or "udp:5514" in src:
        return "opnsense", "network"
    
    if "nginx" in st or "juiceshop" in st or "access.log" in src:
        return "juiceshop", "web"

    return "unknown", "unknown"

def sanitize_ip(val):
    if not val: return None
    v = val.strip()
    if v in ["-", ""]: return None
    return v

def normalize_event(row):
    # --- 0. Noise / Metric Filtering ---
    # Filter out raw metric lines (e.g. "0.00      0.00      0.00")
    # This prevents them from being parsed as syslog with host="0.00"
    raw_payload_check = (row.get("raw_text") or "").strip()
    if raw_payload_check and raw_payload_check[0].isdigit() and "     " in raw_payload_check:
        # Heuristic: starts with digit and has wide spacing implies vmstat/sar output
        return {}

    # ... (keeping existing logic start)
    raw_json = row.get("raw_json") or {}
    if isinstance(raw_json, str):
        try: raw_json = json.loads(raw_json)
        except: raw_json = {}
        
    sourcetype = row["sourcetype"]
    source = row["source"]
    host = row["host"]
    
    vendor, kind = classify_vendor(row, sourcetype, source)
    
    out = {
        "vendor": vendor,
        "event_kind": kind,
        "host": host,
        "source": source,
        "sourcetype": sourcetype,
        "sourcetype": sourcetype,
        "event_time": row.get("event_time"), # Safe access, fallback handled in run_batch or below
        "src_ip": None, "dest_ip": None, "username": None,
        "src_ip": None, "dest_ip": None, "username": None,
        "rule_id": None, "signature": None, "severity": None,
        "http_method": None, "http_path": None, "status_code": None,
        "extras": {} 
    }

    raw_text = row.get("raw_text") or raw_json.get("_raw") or ""
    message = raw_json.get("Message") or raw_text

    if vendor == "wazuh" or vendor == "sysmon" or vendor == "windows":
        extracted = extract_winevent_message(message)
        out.update(extracted)
        
        # Windows Severity Mapping
        # WinEventLog: Type="Error"|"Warning"|"Information" or ["Information", "Not persistent"]
        win_type = raw_json.get("Type") or raw_json.get("Level") or raw_json.get("LevelDisplayName")
        if win_type:
            # Handle list (e.g. from XmlWinEventLog)
            if isinstance(win_type, list):
                wt = " ".join([str(x) for x in win_type]).lower()
            else:
                wt = str(win_type).lower()
                
            if "error" in wt or "crit" in wt: out["severity"] = 7
            elif "warn" in wt: out["severity"] = 4
            elif "info" in wt: out["severity"] = 1
        
        # Rule Metadata (Wazuh specific)
        if "rule" in raw_json:
            rule = raw_json["rule"]
            if isinstance(rule, dict):
                out["signature"] = rule.get("description")
                # Ensure wazuh level (0-15) is mapped or used
                # Wazuh Levels: 12+=High(3), 7-11=Med(2), 0-6=Low(1)
                lev = rule.get("level")
                if lev:
                    try:
                        ilev = int(lev)
                        if ilev >= 12: out["severity"] = 7 # Was 3
                        elif ilev >= 7: out["severity"] = 4 # Was 2
                        else: out["severity"] = 1
                    except:
                        out["severity"] = str(lev)

                # Wazuh Rule ID
                if not out["rule_id"]:
                    out["rule_id"] = str(rule.get("id"))
                
                # Check for specific rule groups for event_kind
                groups = rule.get("groups", [])
                if "authentication_failed" in groups: out["event_kind"] = "alert"

        if "EventCode" in raw_json:
            out["rule_id"] = str(raw_json["EventCode"])
            
        # Fallback Signature for WinEventLog / Wazuh
        if not out["signature"]:
            if out["rule_id"]:
                out["signature"] = "EventCode={}".format(out["rule_id"])
            elif extracted.get("win_source"):
                out["signature"] = "SourceName={}".format(extracted.get("win_source"))
            elif out["rule_id"]: # Fallback if only rule_id exists
                 out["signature"] = "RuleID={}".format(out["rule_id"])
        
        if out["rule_id"] == "3": out["event_kind"] = "network"
        # 4625 = Auth Fail -> Alert
        if out["rule_id"] == "4625": 
            out["event_kind"] = "alert"
            out["severity"] = 2 # At least warning
        if out["rule_id"] == "4624": out["event_kind"] = "auth"
        if out["rule_id"] == "5156": out["event_kind"] = "network"

        # LAB BURST OVERRIDE (demo/test only)
        if out.get("rule_id") == "4625":
            u = (out.get("username") or "").upper()
            if u.startswith("FAIL_LAB_BURST") or "LAB_BURST" in u:
                out["severity"] = 7
                out["event_kind"] = "alert"
                out["signature"] = out.get("signature") or "LAB_BURST tagged auth failure"
                out["extras"]["lab_burst"] = True

    elif vendor == "juiceshop":
        # Nginx extraction
        extracted = extract_nginx(raw_text)
        if extracted:
            out["src_ip"] = extracted.get("src_ip")
            out["http_method"] = extracted.get("http_method")
            out["http_path"] = extracted.get("http_path")
            out["status_code"] = extracted.get("http_status")
        
        # Fallback to JSON fields
        if not out["src_ip"]: out["src_ip"] = raw_json.get("clientip")
        
        # Entity/Host Mapping
        # prefer host from row, else dest_ip / dvc / container name
        if not out["host"] or out["host"] == "unknown":
            out["host"] = out["dest_ip"] or raw_json.get("dvc") or raw_json.get("container_name") or "juiceshop"

        # App Log Handling (errors/warns/info)
        if not out["status_code"]:
            # Use the first few words of the message as signature for app logs
            # e.g. "info: Required file vendor.js is present" -> "info: Required file vendor.js..."
            clean_msg = message.strip()
            if clean_msg:
                 # Truncate to reasonable length for signature
                 out["signature"] = (clean_msg[:50] + '..') if len(clean_msg) > 50 else clean_msg
            
            lower_msg = clean_msg.lower()
            if "error:" in lower_msg:
                out["event_kind"] = "alert"
                out["severity"] = "error" # Explicit severity for bad_event_count
            elif "warn:" in lower_msg:
                 out["severity"] = "warn"

    elif vendor == "opnsense":
        # Prioritize _raw from DB (Splunk raw) over raw_text if available
        # Suricata and Zenarmor often have the real payload in _raw inside raw_json
        syslog_payload = raw_json.get("_raw") or raw_text or ""
        
        m = RE_IP.search(syslog_payload)
        if m: out["src_ip"] = m.group(1)
        
        # 1. Try JSON fields first (if parsed by Splunk)
        if "alert" in raw_json:
            out["event_kind"] = "ids"
            out["signature"] = raw_json["alert"].get("signature")
            out["rule_id"] = str(raw_json["alert"].get("signature_id"))
            out["src_ip"] = raw_json.get("src_ip")
            out["dest_ip"] = raw_json.get("dest_ip")
            
        # 2. Fallback to Regex on Syslog Payload
        else:
            # Suricata [1:234:5] Signature [Class...] OR just [Classification:...]
            has_suricata = RE_SURICATA_SYSLOG.search(syslog_payload)
            
            if has_suricata:
                # Extract rule ID [1:2:3]
                m_sid = re.search(r"\[(\d+:\d+:\d+)\]", syslog_payload)
                if m_sid: out["rule_id"] = m_sid.group(1)
                
                # Refined: Look for [d:d:d] <text> [Classification
                # Capture text roughly before [Classification
                m_sig_clean = re.search(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[Classification:", syslog_payload)
                if m_sig_clean:
                    out["signature"] = m_sig_clean.group(1).strip()
                else:
                    # Fallback
                    m_sig = re.search(r"\]\s+(.*?)\s+\[Classification:", syslog_payload)
                    if m_sig: 
                         out["signature"] = m_sig.group(1).strip()
                
                out["event_kind"] = "ids" # Tag as IDS explicitly
                
                # Check Priority
                m_prio = re.search(r"Priority: (\d+)", syslog_payload)
                if m_prio:
                    try:
                        prio = int(m_prio.group(1))
                        # Suricata: 1=High, 2=Med, 3=Low
                        if prio == 1: 
                            out["severity"] = 7
                            out["event_kind"] = "alert"
                        elif prio == 2: 
                            out["severity"] = 4
                            out["event_kind"] = "alert" # Maybe alert on medium?
                        elif prio == 3: 
                            out["severity"] = 1
                    except: pass
            
            # Zenarmor Flow JSON Parsing
            if "zenarmor: {" in syslog_payload:
                try:
                    z_json_str = syslog_payload.split("zenarmor: ", 1)[1].strip()
                    z_data = json.loads(z_json_str)
                    
                    is_blocked = (z_data.get("is_blocked") == 1)
                    action = "blocked" if is_blocked else "allowed"
                    proto = z_data.get("app_proto") or z_data.get("app_name") or z_data.get("transport_proto") or "unknown"
                    direction = z_data.get("direction") or "unknown"
                    
                    out["signature"] = "zenarmor:{}:{}:{}".format(action, proto, direction)
                    out["rule_id"] = "flow:{}".format(proto)
                    out["event_kind"] = "network"
                    
                    if is_blocked:
                         out["event_kind"] = "alert"
                         out["severity"] = 4
                    
                    if z_data.get("src_ip"): out["src_ip"] = z_data.get("src_ip")
                    if z_data.get("dst_ip"): out["dest_ip"] = z_data.get("dst_ip")
                    
                except:
                    pass

            # Zenarmor: action allowed zenarmor.check...
            if not out["signature"]:
                m_zen = RE_ZENARMOR_SYSLOG.search(syslog_payload)
                if m_zen:
                    action = m_zen.group(1)
                    sig_slug = m_zen.group(2)
                    out["signature"] = "{} {}".format(action, sig_slug)
                    out["rule_id"] = sig_slug
                    out["event_kind"] = "network"

        if not out["signature"]:
            out["signature"] = raw_json.get("event_type")

    # --- Final Polish ---
    # Ensure severity is normalized to STRICT INT
    final_sev = 0 # Default to 0 (unknown/none)
    if out["severity"]:
        s_str = str(out["severity"]).strip().lower()
        if s_str in ["error", "critical", "high", "err", "severe"]:
            final_sev = 7
        elif s_str in ["warn", "medium", "warning"]:
            final_sev = 4
        elif s_str in ["info", "low", "informational"]:
            final_sev = 1
        elif s_str == "debug":
            final_sev = 0
        else:
            # Try parsing integer
            try: final_sev = int(s_str)
            except: final_sev = 0
    
    out["severity"] = final_sev

    # If host looks like a float (metric artifact), strictly unknown it
    if out["host"]:
        out["host"] = out["host"].strip()
        if re.match(r"^\d+\.\d+$", out["host"]) and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", out["host"]):
             out["host"] = "unknown"

    out["src_ip"] = sanitize_ip(out["src_ip"])
    out["dest_ip"] = sanitize_ip(out["dest_ip"])

    # --- Final Polish: Infra Override ---
    # Catch-all for HEC/Pipeline noise
    if out["host"] and "8088" in out["host"]:
        out["vendor"] = "infra"
        out["event_kind"] = "metric"
        out["severity"] = 0 
        out["signature"] = "pipeline_noise"

    # Global Rule ID Fallback (Syslog/Zenarmor/Other)
    if not out["rule_id"] and out["signature"]:
        # Hash signature to get a stable ID
        import hashlib
        out["rule_id"] = hashlib.md5(out["signature"].encode("utf-8")).hexdigest()[:8]
    elif not out["rule_id"]:
        # Last resort: hash vendor + event_kind
        import hashlib
        fallback = "{}:{}".format(vendor, kind)
        out["rule_id"] = hashlib.md5(fallback.encode("utf-8")).hexdigest()[:8]
    
    # Final Signature Fallback
    if not out["signature"]:
        if vendor == "juiceshop" and out["http_method"]:
            out["signature"] = "{} {}".format(out["http_method"], out["http_path"] or "/")
        else:
            out["signature"] = "{}:{}".format(vendor, kind)

    # 3. Extras
    out["extras"] = {k:v for k,v in raw_json.items() if k not in ["_raw", "_time", "_cd", "Message"]}

    return out

# --- RUNNER ---

def run_batch(limit=1000):
    conn = get_connection()
    try:
        with conn, conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("""
                SELECT r.* 
                FROM raw_events r
                LEFT JOIN normalized_events n ON n.raw_id = r.id
                WHERE n.raw_id IS NULL
                ORDER BY r.id ASC
                LIMIT %s
            """, (limit,))
            
            rows = cur.fetchall()
            if not rows: return 0
            
            print("[normalize] fetched {} rows".format(len(rows)))
            
            insert_rows = []
            for r in rows:
                try:
                    norm = normalize_event(r)
                except Exception as e:
                    print(f"[normalize] error processing raw_id {r.get('id')}: {e}")
                    continue
                if not norm:
                    continue  # Skip filtered/metric events
                
                # Safe event_time extraction
                evt_time = norm.get("event_time") or r.get("event_time") or r.get("raw_json", {}).get("_time")
                if not evt_time:
                    # Fallback to ingestion time if available, or skip
                    # Ideally we don't want to skip if we can just use "now", but for historical data "now" is wrong.
                    # Let's try raw_json timestamp, else skip.
                    # As a last resort for robustness:
                    if "timestamp" in r: evt_time = r["timestamp"]
                    
                if not evt_time:
                    print(f"[normalize] skipping raw_id {r.get('id')} - no event_time")
                    continue

                insert_rows.append((
                    r["id"],
                    evt_time,
                    norm["vendor"],
                    norm["event_kind"],
                    norm["source"],
                    norm["sourcetype"],
                    norm["host"],
                    norm["src_ip"],
                    norm["dest_ip"],
                    norm["username"],
                    norm["rule_id"],
                    norm["signature"],
                    norm["severity"],
                    norm["http_method"],
                    norm["http_path"],
                    norm["status_code"]
                ))
            
            sql = """
                INSERT INTO normalized_events (
                    raw_id, event_time, vendor, event_kind,
                    source, sourcetype, host,
                    src_ip, dest_ip, username,
                    rule_id, signature, severity,
                    http_method, http_path, http_status
                ) VALUES %s
                ON CONFLICT (raw_id) DO NOTHING
            """
            execute_values(cur, sql, insert_rows)
            return len(insert_rows)
            
    finally:
        conn.close()

def main():
    # Process batches until caught up, then exit so run.py can trigger features.py
    # This prevents the "infinite loop blocking features" bug
    while True:
        try:
            count = run_batch(limit=5000)
            if count > 0:
                print("[normalize] processed {} events".format(count))
            else:
                # No more rows, exit
                print("[normalize] caught up, exiting.")
                break
        except Exception as e:
            print("[normalize] error: {}".format(e))
            time.sleep(5)
            # On error, break to allow retry by scheduler
            break

if __name__ == "__main__":
    main()
