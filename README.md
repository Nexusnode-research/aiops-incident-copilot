# AIOps Signal Pipeline

A specialized security telemetry pipeline that transforms noisy raw logs into high-fidelity detection signals and correlated incidents.

## The Problem
Security analysts are overwhelmed by raw log volume (syslog, Windows Events, firewall logs). Traditional SIEMs often ingest everything into a "swamp" without structuring it effectively for automation. This project demonstrates a **pipeline-first approach**: converting raw chaos into structured, typed, and linked "signals" *before* they reach the analyst.

## Architecture

```ascii
[ Raw Telemetry ] 
(Syslog, WinEvent, Web)
       │
       ▼
   [ WORKER ] ────────────────────────┐
   │ 1. Seed/Ingest (Python)          │
   │ 2. Normalize (Regex/JSON)        │
   │ 3. Feature Extraction (SQL)      │    [ POSTGRES DB ]
   │ 4. Detect Signals (Logic)        │ ◄── (Unified Store)
   │ 5. Correlate Incidents           │ 
   └──────────────────────────────────┘
                 │
                 ▼
          [ API / DASHBOARD ]
          (FastAPI / Dash)
```

## Data Flow

1.  **Raw Events**: Ingested as JSON blobs (sourcetype, raw_text).
2.  **Normalized**: Typed field extraction (src_ip, user, http_status, vendor, severity).
3.  **Features**: Time-series metrics aggregated by 1m/5m buckets (e.g., `auth_fail_count` per host).
4.  **Signals**: Anomalies detected from features (e.g., "Auth Fail Spike > 3x Baseline") or critical signature matches.
5.  **Incidents**: Related signals grouped by Entity (Host/User) and Time Window.

## Demo Video

[![Demo Video](https://img.youtube.com/vi/58E9QjJEZag/0.jpg)](https://youtu.be/58E9QjJEZag)

## How to Run (One-Command Demo)

To run in **Demo Mode**, uncomment these lines in `docker-compose.yml`:
```yaml
      SEED_ON_STARTUP: "true" # Demo Mode: Seed sample data
      SPLUNK_INGEST: "false"  # Demo Mode: Disable Splunk connection
```

### Prerequisites
*   Docker & Docker Compose
*   Python 3.12+ (if running scripts locally)

### Quick Start
Run the full stack (Worker, API, Dashboard, DB) with clean sample data:

```bash
# 1. Reset and Build (Clean Slate)
docker compose down -v --remove-orphans
docker compose up --build -d

# 2. Watch the Pipeline (Seed -> Normalize -> Signals)
docker compose logs -f worker
```

### Verify Success
After the worker finishes the `[seed]` and `[loop]` steps, check for errors:

```bash
# Should return nothing
docker compose logs worker | Select-String -Pattern "error|does not exist|Traceback"
```

### Dashboard
Visit `http://localhost:8050` to view the generated Incidents and Signals.

## Project Structure

*   `services/worker`: Core ETL pipeline (Normalize, Features, Detect, Correlate).
*   `services/api`: FastAPI backend for data retrieval.
*   `services/dashboard`: Plotly Dash UI for visualization.
*   `sql/init.sql`: Database schema definition (Raw -> Normalized -> Incidents).

## Tech Stack
*   **Language**: Python 3.12
*   **Database**: PostgreSQL 15
*   **Orchestration**: Docker Compose
*   **Frontend**: Plotly Dash
