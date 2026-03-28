import uuid
import json
import os
import subprocess
from datetime import datetime, timezone
from cortex_lite.config import CadmiumTheme as ct
from cortex_lite.census.arp_reader import get_arp_table
from cortex_lite.auditor.constitution_loader import load_constitution
from cortex_lite.auditor.auditor_general import AuditorGeneral
from cortex_lite.utils.reporter import summarize_session
from cortex_lite.census.mdns_listener import scan as mdns_scan

import threading
import itertools
import sys
import time

class Spinner:
    def __init__(self, message):
        self.message = message
        self._spinning = False
        self._thread = None

    def __enter__(self):
        self._spinning = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self):
        for char in itertools.cycle('|/-\\'):
            if not self._spinning:
                break
            sys.stderr.write(f'\r{self.message} {char}')
            sys.stderr.flush()
            time.sleep(0.1)

    def __exit__(self, *args):
        self._spinning = False
        self._thread.join()
        sys.stderr.write('\r' + ' ' * (len(self.message) + 4) + '\r')
        sys.stderr.flush()


# --- CONFIGURATION ---
CONFIG = {
    "admin_mac": "90:09:d0:51:ed:f0",  
    "gateway_ip": "192.168.0.1",       
    "auditor_ip": "192.168.0.5",       
    "model": "llama3.2:3b",
    "log_path": "audit/audit.jsonl"
}

def log_event(event_type, agent, branch, payload, session_id, articles=None):
    """Writes a Section 9 compliant record to the JSONL log."""
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent": agent,
        "branch": branch,
        "event_type": event_type,
        "session_id": session_id,
        "articles_touched": articles or [],
        "payload": payload
    }
    os.makedirs(os.path.dirname(CONFIG["log_path"]), exist_ok=True)
    with open(CONFIG["log_path"], "a") as f:
        f.write(json.dumps(record) + "\n")

class CensusTaker:
    def __init__(self, interface="wlp3s0", gateway_ip="192.168.0.1"):
        self.interface = interface
        self.gateway_ip = gateway_ip

    def active_survey(self):
        """Forces hidden devices in the other building to appear."""
        print(ct.paint(f"[*] Surveying building-to-building bridge...", ct.YELLOW))
        subnet = ".".join(self.gateway_ip.split('.')[:-1])
        processes = []
        for i in range(1, 255):
            target = f"{subnet}.{i}"
            p = subprocess.Popen(
                ["ping", "-c", "1", "-W", "1", target],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            processes.append(p)
        for p in processes:
            p.wait()
        os.system("sleep 2")

def main():
    current_session = str(uuid.uuid4()) 

    print(ct.paint(f"\n{ct.BOLD}CADMIUM CORTEX -- Constitutional Audit", ct.BLUE))
    print(ct.paint(f"Session: {current_session}\n", ct.BLUE))

    census = CensusTaker(interface="wlp3s0", gateway_ip=CONFIG["gateway_ip"])
    census.active_survey()

    try:
        # 1. Legislative: Load Constitution
        const_text = load_constitution()
        print(ct.paint("[-] Constitution loaded and versioned.", ct.GREEN))

        # 2. Legislative: Census Collection
        raw_devices = get_arp_table(interface=census.interface)
        print(ct.paint("[*] Running mDNS scan...", ct.YELLOW))
        mdns_data = mdns_scan(listen_seconds=10)
        print(ct.paint(f"[-] mDNS returned {len(mdns_data)} device(s).", ct.GREEN))
        print(ct.paint(f"[-] Census captured {len(raw_devices)} devices.", ct.GREEN))
        
        # --- 3. JUDICIAL DELIBERATION ---
        auditor_instance = AuditorGeneral(CONFIG["model"], const_text)
        
        registry_summary = []
        for d in raw_devices:
            mdns_info = mdns_data.get(d['ip'], {})
            registry_summary.append({
            "device_id": d['mac'].replace(':', ''),
            "ip": d['ip'],
            "mac": d['mac'],
            "vendor": "Unknown",
            "hostname": mdns_info.get("hostname"),
            "services": mdns_info.get("services", []),
    })

        print(ct.paint(f"[*] Auditor deliberating on {len(registry_summary)} devices...", ct.YELLOW))
        
        # High-stability batching
        batch_size = 4  # Dropped to 4 for stability
        all_findings = []
        
        for i in range(0, len(registry_summary), batch_size):
            batch = registry_summary[i : i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = -(-len(registry_summary) // batch_size)  # ceiling division
    
            msg = ct.paint(f"    > Batch {batch_num}/{total_batches} ({len(batch)} devices)", ct.YELLOW)
    
            try:
                os.system("sleep 1")
                with Spinner(msg):
                    batch_findings = auditor_instance.audit(
                        batch,
                        gateway_ip=CONFIG["gateway_ip"],
                        admin_id=CONFIG["admin_mac"]
                    )
        
                if batch_findings:
                    print(ct.paint(f"      [+] {len(batch_findings)} findings.", ct.GREEN))
                    all_findings.extend(batch_findings)
                else:
                    print(f"      [-] No violations.")

            except Exception as e:
                print(ct.paint(f"    [!] Batch {batch_num} failed: {e}", ct.RED))
        # Log all findings to your JSONL
        for finding in all_findings:
            log_event(
                event_type="accusation",
                agent="auditor_general",
                branch="judicial",
                payload=finding,
                session_id=current_session,
                articles=[finding.get("article", "Unknown")]
            )

    except Exception as e:
        print(ct.paint(f"[!] Critical Substrate Failure: {e}", ct.RED))
    
    finally:
        # 4. Reporting
        summarize_session(CONFIG["log_path"], current_session)
        print(f"SESSION_ID={current_session}")

if __name__ == "__main__":
    main()
