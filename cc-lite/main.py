import uuid
import json
import os
import subprocess
from datetime import datetime, timezone
from cortex_lite.config import CadmiumTheme as ct
from cortex_lite.census.arp_reader import get_arp_table
from cortex_lite.census.oui_lookup import OUILookup
from cortex_lite.census.registry import DeviceRegistry
from cortex_lite.auditor.constitution_loader import load_constitution
from cortex_lite.auditor.auditor_general import AuditorGeneral
from cortex_lite.utils.reporter import summarize_session

# --- CONFIGURATION (Tonight's Defaults) ---
CONFIG = {
    "admin_mac": "90:09:d0:51:ed:f0",  # CHANGE THIS to your actual MAC
    "gateway_ip": "68.72.96.95",       # CHANGE THIS to your router IP
    "auditor_ip": "192.168.0.5"
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

class CensusTaker:
    def __init__(self, interface="wlp3s0", gateway_ip="192.168.0.1"):
        self.interface = interface
        self.gateway_ip = gateway_ip

    def active_survey(self):
        """
        Forces all 254 potential IPs to respond, 
        populating the ARP table for the Auditor.
        """
        print(ct.paint(f"[*] Surveying building-to-building bridge...", ct.YELLOW))
        
        # Extract the subnet (e.g., 192.168.0)
        subnet = ".".join(self.gateway_ip.split('.')[:-1])
        
        # Parallel ping sweep (Linux/Bash style)
        for i in range(1, 255):
            target = f"{subnet}.{i}"
            # Launch in background (&) to keep it fast
            subprocess.Popen(
                ["ping", "-c", "1", "-W", "1", target],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        
        # Give the network a second to settle
        os.system("sleep 2")

    def collect(self):
        """
        This is where your existing logic to read 
        /proc/net/arp or 'ip neigh' would go.
        """
        # (Your existing collection logic here)
        pass

def main():
    # Now local - unique per run
    session_id = str(uuid.uuid4()) 

    print(ct.paint(f"\n{ct.BOLD}CADMIUM CORTEX -- Constitutional Audit", ct.BLUE))
    print(ct.paint(f"Session: {session_id}\n", ct.BLUE))

    # 1. Initialize the Census Taker
    census = CensusTaker(interface="wlp3s0", gateway_ip="192.168.0.1")

    # 2. Perform Active Survey (Find those 4 hidden IoT devices)
    census.active_survey()

    # 3. Load Constitution & Run Audit
    try:
        const_text = load_constitution()
        # ... your existing logic ...
        
    finally:
        # 4. Use the local session_id for the summary
        summarize_session("audit/audit.jsonl", session_id)
if __name__ == "__main__":
    main()
