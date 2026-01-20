
import os
import psycopg2
import pandas as pd
from datetime import datetime, timedelta

def get_connection():
    db_url = os.environ.get("DATABASE_URL", "postgresql://aiops:aiops@postgres:5432/aiops")
    if db_url.startswith("postgresql+psycopg2://"):
        db_url = "postgresql://" + db_url.split("postgresql+psycopg2://", 1)[1]
    return psycopg2.connect(db_url)

def get_incidents(hours=24, status_filter=None):
    """
    Fetch incidents within the last X hours.
    """
    conn = get_connection()
    try:
        query = """
            SELECT 
                id, title, status, severity, score, 
                root_entity_type, root_entity_id, 
                start_time, last_update_time, 
                to_char(last_update_time + INTERVAL '2 HOURS', 'YYYY-MM-DD HH24:MI:SS') as last_update_str,
                (SELECT count(*) FROM incident_evidence WHERE incident_id = incidents.id) as evidence_count
            FROM incidents
            WHERE last_update_time >= NOW() - INTERVAL '%s hours'
        """ % (hours,)
        
        if status_filter:
            query += f" AND status = '{status_filter}'"
            
        query += " ORDER BY last_update_time DESC"
        
        df = pd.read_sql(query, conn)
        return df
    finally:
        conn.close()

def get_incident_details(incident_id):
    """
    Fetch single incident row.
    """
    conn = get_connection()
    try:
        query = "SELECT * FROM incidents WHERE id = %s"
        df = pd.read_sql(query, conn, params=(incident_id,))
        if not df.empty:
            return df.iloc[0]
        return None
    finally:
        conn.close()

def get_incident_evidence(incident_id):
    """
    Fetch all signals for an incident, sorted by event_time ASC.
    """
    conn = get_connection()
    try:
        query = """
            SELECT 
                s.id, s.event_time, s.window_start, s.signal_name, s.severity, s.score, 
                s.entity_type, s.entity_id, s.metadata,
                to_char(s.event_time + INTERVAL '2 HOURS', 'YYYY-MM-DD HH24:MI:SS') as time_str
            FROM signal_events s
            JOIN incident_evidence ie ON s.id = ie.signal_id
            WHERE ie.incident_id = %s
            ORDER BY s.event_time ASC
        """
        df = pd.read_sql(query, conn, params=(incident_id,))
        return df
    finally:
        conn.close()
