
import pandas as pd
import json
import os
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")

def ollama_brief(system_prompt: str, user_prompt: str) -> str:
    """
    Calls the local Ollama instance to generate text.
    Uses streaming mode for better responsiveness and fallback handling.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": True,  # Use streaming for better timeout handling
        "options": {"temperature": 0.2}
    }
    try:
        # Quick health check first
        health_check = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        if health_check.status_code != 200:
            raise Exception("Ollama health check failed")
        
        # Stream the response
        r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=60, stream=True)
        r.raise_for_status()
        
        content = ""
        for line in r.iter_lines():
            if line:
                try:
                    chunk = json.loads(line)
                    if "message" in chunk and "content" in chunk["message"]:
                        content += chunk["message"]["content"]
                    if chunk.get("done", False):
                        break
                except json.JSONDecodeError:
                    continue
        
        if not content:
            raise Exception("Empty response from Ollama")
        
        return content
    except requests.exceptions.Timeout:
        raise Exception("Ollama request timed out. The model may be loading or stuck. Try restarting Ollama.")
    except Exception as e:
        raise Exception(f"Error communicating with Ollama: {e}")

def generate_splunk_queries(entity_type, entity_id, start_time, end_time):
    """
    Generate ready-to-run Splunk queries based on the entity.
    """
    queries = []
    
    # Base Search
    base = f"index=* "
    time_range = f"earliest=\"{start_time}\" latest=\"{end_time}\""
    
    if entity_type in ['host', 'ip', 'src_ip', 'dest_ip']:
        queries.append({
            "title": "General Activity",
            "query": f"{base} (host=\"{entity_id}\" OR src_ip=\"{entity_id}\" OR dest_ip=\"{entity_id}\") | table _time, source, sourcetype, event_id, TransportProtocol, src_ip, dest_ip, user"
        })
        
        queries.append({
            "title": "Authentication Failures",
            "query": f"{base} (host=\"{entity_id}\" OR src_ip=\"{entity_id}\") \"failed\" OR \"failure\" OR EventCode=4625 | stats count by user, src_ip"
        })
    
    if entity_type == 'user':
        queries.append({
            "title": "User Activity",
            "query": f"{base} user=\"{entity_id}\" | stats count by host, sourcetype, EventCode"
        })
        
    return queries

def generate_ai_brief(incident, signals) -> str:
    """
    Generates an Incident Brief using the local LLM.
    Falls back to heuristic brief if Ollama is unavailable.
    """
    if signals.empty:
        evidence_str = "No specific evidence found."
    else:
        # Deduplicate and sort evidence for the prompt
        deduped = signals.drop_duplicates(subset=['signal_name', 'entity_id', 'time_str'])
        top_sigs = deduped.sort_values(by=['severity', 'event_time'], ascending=[False, False]).head(25)
        
        evidence_str = "Top 25 Evidence Items:\n"
        for _, row in top_sigs.iterrows():
            evidence_str += f"- [{row['time_str']}] {row['signal_name']} (Sev: {row['severity']}) on {row['entity_id']}\n"

    # 1. System Prompt
    system_prompt = (
        "You are a Senior SOC Analyst writing an Incident Brief for a security alert. "
        "Your goal is to be factual, concise, and actionable.\n"
        "Guidelines:\n"
        "- Summarize the scope and timeline clearly.\n"
        "- Cite specific timestamps and entities from the provided evidence.\n"
        "- Assess the potential threat level based on the evidence.\n"
        "- Provide 3 concrete recommended actions for investigation.\n"
        "- Output clean Markdown formatting."
    )

    # 2. User Prompt
    user_prompt = (
        f"Incident Title: {incident['title']} (ID: {incident['id']})\n"
        f"Severity: {incident['severity']} | Score: {incident['score']}\n"
        f"Root Entity: {incident['root_entity_type']}:{incident['root_entity_id']}\n"
        f"Timeline: {incident['start_time']} to {incident['last_update_time']}\n\n"
        f"EVIDENCE:\n{evidence_str}\n\n"
        "Please generate the executive incident brief."
    )

    try:
        return ollama_brief(system_prompt, user_prompt)
    except Exception as e:
        # Fallback to heuristic brief with a note
        heuristic = generate_heuristic_brief(incident, signals)
        return f"**Note:** AI generation unavailable ({str(e)}). Showing heuristic analysis:\n\n{heuristic}"

def generate_heuristic_brief(incident, signals):
    """
    Generates a Markdown Brief using heuristics (Evidence Grounding).
    KEY: Renamed from generate_brief for clarity.
    """
    if signals.empty:
        return "No evidence found for this incident."
        
    root_entity = f"{incident['root_entity_type']}:{incident['root_entity_id']}"
    root_entity = f"{incident['root_entity_type']}:{incident['root_entity_id']}"
    # Shift to SAST (+2)
    start_str = (incident['start_time'] + pd.Timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
    last_update = (incident['last_update_time'] + pd.Timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
    
    # --- STATISTICS ---
    # Deduplicate for summary stats (unique signal types)
    unique_types = signals['signal_name'].unique()
    total_signals = len(signals)
    unique_evidence_count = len(signals.drop_duplicates(subset=['signal_name', 'entity_id', 'window_start']))
    
    # Top Signal Types
    top_types_list = signals['signal_name'].value_counts().head(3).index.tolist()
    top_types_str = ", ".join(top_types_list)
    
    # 1. Executive Summary
    summary = f"**Executive Summary (Heuristic)**\n"
    summary += f"Incident involving **{root_entity}** detected from **{start_str}** to **{last_update}**. "
    summary += f"The system correlated **{total_signals} signals** (collapsed to {unique_evidence_count} distinct events) into an incident with Score **{incident['score']:.0f}** (Severity {incident['severity']}).\n\n"
    summary += f"Primary detection types: {top_types_str}.\n\n"
    
    # 2. Key Evidence (Deduplicated, Top 5)
    summary += "**Key Evidence**\n"
    # Dedup logic: keep first occurrence of each (signal+entity+time)
    deduped = signals.drop_duplicates(subset=['signal_name', 'entity_id', 'time_str'])
    # Sort by Severity DESC, then Time DESC
    top_sigs = deduped.sort_values(by=['severity', 'event_time'], ascending=[False, False]).head(5)
    
    for _, row in top_sigs.iterrows():
        summary += f"* **{row['time_str']}**: {row['signal_name']} (Sev {row['severity']}) - {row['entity_id']}\n"
        
    summary += "\n"
    
    # 3. Recommended Actions (Safe Checks)
    summary += "**Recommended Actions**\n"
    summary += f"* [ ] Review activity for **{incident['root_entity_id']}** between {start_str} and {last_update}.\n" # Context aware time
    
    if 'host' in incident['root_entity_type']:
        summary += f"* [ ] specific Event Logs (Security) for EventID 4625 (Logon Fail).\n"
        summary += f"* [ ] Check active processes and network connections on {incident['root_entity_id']}.\n"
    elif 'ip' in incident['root_entity_type']:
        summary += f"* [ ] Check firewall logs for traffic involving {incident['root_entity_id']}.\n"
        summary += f"* [ ] Verify if {incident['root_entity_id']} is a known corporate asset or external threat.\n"
        
    summary += "\n"
    
    return summary
