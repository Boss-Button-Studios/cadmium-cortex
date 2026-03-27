import uuid
import json
import os
from datetime import datetime, timezone
from cortex_lite.config import CadmiumTheme as ct
from cortex_lite.census.arp_reader import get_arp_table
from cortex_lite.census.oui_lookup import OUILookup
from cortex_lite.census.registry import DeviceRegistry
from cortex_lite.auditor.constitution_loader import load_constitution
from cortex_lite.auditor.auditor_general import AuditorGeneral

# --- CONFIGURATION (Tonight's Defaults) ---
CONFIG = {
    "admin_mac": "90:09:d0:51:ed:f0",  # CHANGE THIS to your actual MAC
    "gateway_ip": "192.168.0.1",       # CHANGE THIS to your router IP
    "model": "qwen2.5-coder:1.5b",
    "log_path": "audit/audit.jsonl"
}

def log_event(event_type, agent, branch, payload, articles=None):
    """Writes a Section 9 compliant record to the JSONL log."""
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent": agent,
        "branch": branch,
        "event_type": event_type,
        "session_id": SESSION_ID,
        "articles_touched": articles or [],
        "payload": payload
    }
    with open(CONFIG["log_path"], "a") as f:
        f.write(json.dumps(record) + "\n")

SESSION_ID = str(uuid.uuid4())

def main():
    print(ct.paint(f"\n{ct.BOLD}CADMIUM CORTEX -- Constitutional Audit", ct.BLUE))
    print(ct.paint(f"Session: {SESSION_ID}\n", ct.BLUE))

    # 1. Load Constitution
    try:
        const_text = load_constitution()
        print(ct.paint("[-] Constitution loaded and versioned.", ct.GREEN))
    except Exception as e:
        print(ct.paint(f"[!] Constitutional Error: {e}", ct.RED))
        return

    # 2. Census Taker
    print(ct.paint("[-] Starting Census Taker (ARP scan)...", ct.YELLOW))
    raw_devices = get_arp_table()
    oui = OUILookup()
    registry = DeviceRegistry()
    
    new_count = registry.update_devices(raw_devices, oui)
    
    # Log observations
    for dev_id, data in registry.devices.items():
        log_event("observation", "census_taker", "legislative", data)

    print(ct.paint(f"[-] Census: {len(raw_devices)} devices observed ({new_count} new).", ct.GREEN))

    # 3. Auditor General
    print(ct.paint(f"[-] Running Audit via {CONFIG['model']}...", ct.YELLOW))
    auditor = AuditorGeneral(CONFIG["model"], const_text)
    
    # We hash the admin MAC for the auditor's context
    admin_id = registry._hash_mac(CONFIG["admin_mac"])
    summary = registry.get_audit_summary()
    
    findings = auditor.audit(summary, CONFIG["gateway_ip"], admin_id)

    # 4. Results & Logging
    if not findings:
        print(ct.paint("[-] No constitutional concerns identified.", ct.GREEN))
    else:
        print(ct.paint(f"[!] {len(findings)} potential concerns found:", ct.ORANGE))
        for f in findings:
            color = ct.RED if f['suspicion_level'] == 'high' else ct.ORANGE
            print(ct.paint(f"  • Article {f['article']} [{f['suspicion_level'].upper()}]", color))
            print(f"    Device: {f['device_id'][:12]}... ({f['evidence']})")
            
            log_event(
                "accusation", 
                "auditor_general", 
                "judicial", 
                f, 
                articles=[f['article']]
            )

    print(ct.paint(f"\nAudit log updated: {CONFIG['log_path']}", ct.BLUE))

if __name__ == "__main__":
    main()
