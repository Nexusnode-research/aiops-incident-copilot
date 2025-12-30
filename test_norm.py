
import json
import re

# Load digest
try:
    with open(r"e:\Projects\aiops\samples\digest.json", "r") as f:
        digest = json.load(f)
except:
    print("Could not load digest.json")
    digest = {}

# --- Logic Prototype ---

# 1. Wazuh / Sysmon (WinEventLog) extraction
def extract_winevent(evt):
    msg = evt.get("Message", "")
    data = {}
    
    # Sysmon Code 3: Network connection
    # RuleName: ..., SourceIp: 224.0.0.251, ...
    if "SourceIp:" in msg:
        m = re.search(r"SourceIp:\s*([\d\.]+)", msg)
        if m: data["src_ip"] = m.group(1)
        m = re.search(r"DestinationIp:\s*([\d\.]+)", msg)
        if m: data["dest_ip"] = m.group(1)
        m = re.search(r"User:\s*([^\r\n]+)", msg)
        if m: data["user"] = m.group(1).strip()
    
    # Security 5156: Windows Filtering Platform
    # Source Address: 127.0.0.1
    elif "Source Address:" in msg:
        m = re.search(r"Source Address:\s*([\d\.]+)", msg)
        if m: data["src_ip"] = m.group(1)
        m = re.search(r"Destination Address:\s*([\d\.]+)", msg)
        if m: data["dest_ip"] = m.group(1)
        
    return data

# 2. JuiceShop (Nginx) extraction
# 172.16.58.20 - - [18/Dec/2025:12:43:56 +0000] "GET /... HTTP/1.1" 200 ...
NGINX_RE = re.compile(r'^(\S+) \S+ \S+ \[.*?\] "(.*?) (.*?) .*?" (\d+)')
def extract_nginx(raw):
    m = NGINX_RE.search(raw)
    if m:
        return {
            "src_ip": m.group(1),
            "http_method": m.group(2),
            "http_path": m.group(3),
            "http_status": int(m.group(4))
        }
    return {}

# --- Test Runner ---

print("=== TESTING EXTRACTION LOGIC ===\n")

if "wazuh" in digest:
    print("[WAZUH] Raw Message snippet: " + digest["wazuh"]["_raw"][:50] + "...")
    # Convert _raw to pseudo-events if it's WinEventLog
    # In digest['wazuh'], keys like 'Message' are at top level or inside _raw parsing?
    # Digest has "Message" in the _raw text usually, but Splunk export (JSON) might NOT parse _raw into fields unless we asked.
    # Wait, the sample I saw earlier had "Message=..." inside the _raw string. Splunk export didn't yield fields?
    # Actually, wazuh.json sample showed "Message" inside _raw string. There were no separate fields.
    # I need to parse _raw key-values (LogName=...) if they exist.
    
    # Simple KEY=VALUE parser for WinEventLog _raw
    w_raw = digest["wazuh"]["_raw"]
    w_fields = {}
    for line in w_raw.splitlines():
        if "=" in line:
            parts = line.split("=", 1)
            w_fields[parts[0]] = parts[1]
    
    # Merge message? Message usually spans info.
    # For now test regex on _raw directly
    parsed = extract_winevent({"Message": w_raw})
    print(" -> Extracted: {}".format(parsed))

if "sysmon" in digest:
    print("\n[SYSMON] Raw Message snippet: " + digest["sysmon"]["_raw"][:50] + "...")
    parsed = extract_winevent({"Message": digest["sysmon"]["_raw"]})
    print(" -> Extracted: {}".format(parsed))

if "juiceshop" in digest:
    print("\n[JUICESHOP] Raw: " + digest["juiceshop"]["_raw"][:50] + "...")
    parsed = extract_nginx(digest["juiceshop"]["_raw"])
    print(" -> Extracted: {}".format(parsed))

if "opnsense" in digest:
    print("\n[OPNSENSE] Raw: " + digest["opnsense"]["_raw"][:50] + "...")
    # Basic IP search
    m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", digest["opnsense"]["_raw"])
    print(" -> found IP: " + (m.group(1) if m else "None"))
