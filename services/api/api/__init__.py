import os
import requests
from fastapi import FastAPI, HTTPException
from redis import Redis

app = FastAPI(title="AIOps SOC API", version="0.0.1")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "172.16.58.134")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS", "")

rdb = Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ingest/splunk/once")
def ingest_splunk_once():
    """
    Pull 1 event from Splunk (_internal for now) and push it into Redis list 'events:raw'
    """
    if not SPLUNK_PASS:
        raise HTTPException(status_code=500, detail="SPLUNK_PASS is empty in env")

    # 1) login -> session key
    login_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/auth/login"
    resp = requests.post(
        login_url,
        data={"username": SPLUNK_USER, "password": SPLUNK_PASS},
        verify=False,
        timeout=15,
    )
    if resp.status_code != 200 or "<sessionKey>" not in resp.text:
        raise HTTPException(status_code=401, detail=f"Splunk login failed: {resp.text[:200]}")

    session_key = resp.text.split("<sessionKey>")[1].split("</sessionKey>")[0].strip()

    # 2) export a single event (simple + reliable)
    search_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"
    search = 'search index=_internal | head 1 | eval source_splunk="1"'
    data = {"output_mode": "json"}
    resp2 = requests.post(
        search_url,
        headers={"Authorization": f"Splunk {session_key}"},
        data=data,
        params={"search": search},  # avoids curl-style escaping issues
        verify=False,
        timeout=30,
    )
    if resp2.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Splunk export failed: {resp2.text[:200]}")

    # Splunk export streams JSON lines; take the first line that contains "result"
    line = next((ln for ln in resp2.text.splitlines() if '"result"' in ln), None)
    if not line:
        raise HTTPException(status_code=500, detail="No result line returned by Splunk export")

    # Push raw JSON line; worker will parse later
    rdb.lpush("events:raw", line)
    return {"pushed": 1, "redis_list": "events:raw"}
