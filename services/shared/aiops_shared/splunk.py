import re
import time
import json
import requests
from .config import (
    SPLUNK_SCHEME, SPLUNK_HOST, SPLUNK_MGMT_PORT,
    SPLUNK_USERNAME, SPLUNK_PASSWORD, SPLUNK_VERIFY_SSL
)

BASE = f"{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_MGMT_PORT}"

_session_key = None
_session_key_ts = 0

def _get_session_key() -> str:
    global _session_key, _session_key_ts

    # cache for 30 minutes
    if _session_key and (time.time() - _session_key_ts) < 1800:
        return _session_key

    url = f"{BASE}/services/auth/login"
    data = {"username": SPLUNK_USERNAME, "password": SPLUNK_PASSWORD}
    r = requests.post(url, data=data, verify=SPLUNK_VERIFY_SSL, timeout=30)
    r.raise_for_status()

    m = re.search(r"<sessionKey>([^<]+)</sessionKey>", r.text)
    if not m:
        raise RuntimeError("Splunk login response did not include sessionKey (check credentials/permissions).")

    _session_key = m.group(1)
    _session_key_ts = time.time()
    return _session_key

def export_search(search: str, earliest: str, latest: str = "now", output_mode: str = "json"):
    sk = _get_session_key()
    url = f"{BASE}/services/search/jobs/export"
    data = {
        "search": f"search {search}",
        "earliest_time": earliest,
        "latest_time": latest,
        "output_mode": output_mode,
    }
    headers = {"Authorization": f"Splunk {sk}"}

    r = requests.post(url, data=data, headers=headers, verify=SPLUNK_VERIFY_SSL, timeout=60)
    r.raise_for_status()

    rows = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows
