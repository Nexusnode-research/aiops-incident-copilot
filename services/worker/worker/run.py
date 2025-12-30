import os, time, subprocess

def env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except Exception:
        return int(default)

POLL = env_int("POLL_INTERVAL_SECONDS", 60)
MINUTES = env_int("LOOKBACK_MINUTES", 5)
LIMIT = env_int("LIMIT", 500)
SEED_ON_STARTUP = (os.getenv("SEED_ON_STARTUP", "false").lower() == "true")
# Default to TRUE unless explicitly disabled (safe default for production)
SPLUNK_INGEST = (os.getenv("SPLUNK_INGEST", "true").lower() == "true")
# Legacy support: if DEMO_MODE=true, it means seed=true AND ingest=false
if os.getenv("DEMO_MODE", "false").lower() == "true":
    SEED_ON_STARTUP = True
    SPLUNK_INGEST = False

if SEED_ON_STARTUP:
    print("[worker] Seeding data (Demoe Mode)...")
    subprocess.call(["python", "/app/seed.py"])

if SPLUNK_INGEST:
    print("[worker] Starting standard Splunk polling...")
else:
    print("[worker] Splunk ingestion DISABLED.")

while True:
    rc = 0
    if SPLUNK_INGEST:
        cmd = ["python", "/app/splunk_connector.py", "--minutes", str(MINUTES), "--limit", str(LIMIT)]
        print(f"[loop] running: {' '.join(cmd)}")
        rc = subprocess.call(cmd)
    else:
        # In demo/seed-only mode, we skip splunk ingestion
        pass
    
    # Run normalizer
    # Run normalizer
    cmd_norm = ["python", "/app/worker/normalize.py"]
    print(f"[loop] running: {' '.join(cmd_norm)}")
    subprocess.call(cmd_norm)

    # Run feature extraction
    cmd_feat = ["python", "/app/worker/features.py"]
    print(f"[loop] running: {' '.join(cmd_feat)}")
    subprocess.call(cmd_feat)

    # Run build_signals (Phase 3 logic)
    cmd_signals = ["python", "/app/worker/build_signals.py"]
    print(f"[loop] running: {' '.join(cmd_signals)}")
    subprocess.call(cmd_signals)

    # Run detections
    cmd_detect = ["python", "/app/worker/detections.py"]
    print(f"[loop] running: {' '.join(cmd_detect)}")
    subprocess.call(cmd_detect)

    # Run correlation
    cmd_correlate = ["python", "/app/worker/correlate.py"]
    print(f"[loop] running: {' '.join(cmd_correlate)}")
    subprocess.call(cmd_correlate)
    
    print(f"[loop] exit_code={rc} sleeping {POLL}s\n")
    time.sleep(POLL)
