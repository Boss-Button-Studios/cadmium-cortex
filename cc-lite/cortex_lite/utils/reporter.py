import json
from datetime import datetime

def summarize_session(log_path, session_id):
    print(f"\n{'='*60}")
    print(f"CONSTITUTIONAL AUDIT SUMMARY | SESSION: {session_id}")
    print(f"Generated at: {datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    with open(log_path, 'r') as f:
        for line in f:
            data = json.loads(line)
            # Only process entries belonging to the current run
            if data.get("session_id") == session_id:
                agent = data.get("agent")
                payload = data.get("payload", {})

                if agent == "census_taker":
                    print(f"[CENSUS] Found: {payload.get('vendor')} ({payload.get('observed_ips')[0]})")
                
                elif agent == "auditor_general":
                    article = payload.get("article")
                    severity = payload.get("suspicion_level", "LOW").upper()
                    print(f"\n[!] VIOLATION FOUND: Article {article} [{severity}]")
                    print(f"    Device ID: {payload.get('device_id')[:12]}...")
                    print(f"    Evidence:  {payload.get('evidence')}")
                    print(f"    Rationale: {payload.get('reasoning')}")

    print(f"\n{'='*60}")
