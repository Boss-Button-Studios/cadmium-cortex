import uuid
import json
import os
import subprocess
import threading
import itertools
import sys
import time
from datetime import datetime, timezone
from cortex_lite.config import CadmiumTheme as ct
from cortex_lite.census.arp_reader import get_arp_table
from cortex_lite.census.mdns_listener import scan as mdns_scan
from cortex_lite.auditor.constitution_loader import load_constitution
from cortex_lite.auditor.auditor_general import AuditorGeneral
from cortex_lite.utils.reporter import summarize_session
from cortex_lite.utils.research_logger import write_research_log, write_summary_file
from cortex_lite.census.oui_lookup import OUILookup

# --- CONFIGURATION ---
CONFIG = {
    "admin_mac":   "90:09:d0:51:ed:f0",
    "gateway_ip":  "192.168.0.1",
    "auditor_ip":  "192.168.0.5",
    "model":       "llama3.2:3b",
    "log_path":    "audit/audit.jsonl",
    "batch_size":  4,
    "min_devices": 10
}


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

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

    def __exit__(self, *args):
        self._spinning = False
        self._thread.join()
        sys.stderr.write('\r' + ' ' * (len(self.message) + 4) + '\r')
        sys.stderr.flush()

    def _spin(self):
        for char in itertools.cycle('|/-\\'):
            if not self._spinning:
                break
            sys.stderr.write(f'\r{self.message} {char}')
            sys.stderr.flush()
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def log_event(event_type, agent, branch, payload, session_id, articles=None):
    """Writes a Section 9 compliant record to the JSONL log."""
    record = {
        "event_id":        str(uuid.uuid4()),
        "timestamp":       datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent":           agent,
        "branch":          branch,
        "event_type":      event_type,
        "session_id":      session_id,
        "articles_touched": articles or [],
        "payload":         payload
    }
    os.makedirs(os.path.dirname(CONFIG["log_path"]), exist_ok=True)
    with open(CONFIG["log_path"], "a") as f:
        f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Census
# ---------------------------------------------------------------------------

class CensusTaker:
    def __init__(self, interface="wlp3s0", gateway_ip="192.168.0.1"):
        self.interface = interface
        self.gateway_ip = gateway_ip

    def active_survey(self):
        print(ct.paint("[*] Surveying building-to-building bridge...", ct.YELLOW))
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

# ---------------------------------------------------------------------------
# Read CPU temp just before inference — best proxy for throttle state
# ---------------------------------------------------------------------------
def _read_cpu_temp() -> float | None:
    try:
        with open("/sys/class/thermal/thermal_zone8/temp", "r") as f:
            val = round(int(f.read().strip()) / 1000, 1)
            print(f"DEBUG cpu_temp: {val}", file=sys.stderr)
            return val
    except Exception as e:
        print(f"DEBUG cpu_temp error: {e}", file=sys.stderr)
        return None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    current_session = str(uuid.uuid4())
    session_timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    print(ct.paint(f"\n{ct.BOLD}CADMIUM CORTEX -- Constitutional Audit", ct.BLUE))
    print(ct.paint(f"Session: {current_session}\n", ct.BLUE))

    census = CensusTaker(interface="wlp3s0", gateway_ip=CONFIG["gateway_ip"])
    census.active_survey()

    try:
        # 1. Constitution
        const_text = load_constitution()
        print(ct.paint("[-] Constitution loaded and versioned.", ct.GREEN))

        # 2. Load OUI database once — 3.6MB CSV, don't reload per batch
        oui_db = OUILookup(csv_path="data/oui.csv")
        print(ct.paint(f"[-] OUI database loaded ({len(oui_db.registry)} entries).", ct.GREEN))

        # 3. mDNS
        print(ct.paint("[*] Running mDNS scan...", ct.YELLOW))
        mdns_data = mdns_scan(listen_seconds=10)
        print(ct.paint(f"[-] mDNS returned {len(mdns_data)} device(s).", ct.GREEN))

        # 4. ARP census — conditional sweep
        raw_devices = get_arp_table(interface=census.interface)
        if len(raw_devices) < CONFIG.get("min_devices", 10):
            print(ct.paint("[*] Sparse ARP cache — running active survey...", ct.YELLOW))
            census.active_survey()
            raw_devices = get_arp_table(interface=census.interface)
        print(ct.paint(f"[-] Census captured {len(raw_devices)} devices.", ct.GREEN))

        # 5. Build enriched registry summary
        registry_summary = []
        for d in raw_devices:
            mdns_info = mdns_data.get(d['ip'], {})
            vendor, confidence = oui_db.lookup(d['mac'])

            # Detect locally administered (randomized) MACs
            first_octet = int(d['mac'].replace(':', '').replace('-', '')[0:2], 16)
            locally_administered = bool(first_octet & 0x02)
            if locally_administered:
                vendor = "Unknown (randomized MAC)"
                confidence = "none"

            registry_summary.append({
                "device_id": d['mac'].replace(':', ''),
                "ip": d['ip'],
                "mac": d['mac'],
                "vendor": vendor,
                "oui_confidence": confidence,
                "locally_administered": locally_administered,
                "hostname": mdns_info.get("hostname"),
                "services": mdns_info.get("services", []),
            })

        # 6. Judicial deliberation
        auditor_instance = AuditorGeneral(CONFIG["model"], const_text)
        batch_size = CONFIG["batch_size"]
        total_batches = -(-len(registry_summary) // batch_size)  # ceiling division

        print(ct.paint(
            f"[*] Auditor deliberating on {len(registry_summary)} devices...", ct.YELLOW
        ))

        all_findings = []
        batch_records = []   # for research log

        for i in range(0, len(registry_summary), batch_size):
            batch = registry_summary[i: i + batch_size]
            batch_num = i // batch_size + 1
            msg = ct.paint(
                f"    > Batch {batch_num}/{total_batches} ({len(batch)} devices)", ct.YELLOW
            )

            try:
                time.sleep(1)
                t_start = time.time()
                cpu_temp = _read_cpu_temp()
                with Spinner(msg):
                    result = auditor_instance.audit(
                        batch,
                        gateway_ip=CONFIG["gateway_ip"],
                        admin_id=CONFIG["admin_mac"]
                    )

                # Augment result with batch metadata for research log
                result["batch_index"]        = batch_num
                result["batch_device_count"] = len(batch)
                result["cpu_temp_c"] = cpu_temp
                batch_records.append(result)

                if result["error"]:
                    print(ct.paint(f"    [!] Batch {batch_num} failed: {result['error']}", ct.RED))
                elif result["valid_findings"]:
                    count = len(result["valid_findings"])
                    print(ct.paint(f"      [+] {count} finding(s).", ct.GREEN))
                    all_findings.extend(result["valid_findings"])
                else:
                    print(f"      [-] No violations.")

            except Exception as e:
                print(ct.paint(f"    [!] Batch {batch_num} failed: {e}", ct.RED))
                batch_records.append({
                    "batch_index":        batch_num,
                    "batch_device_count": len(batch),
                    "valid_findings":     [],
                    "rejected_findings":  [],
                    "raw_reply":          "",
                    "duration_seconds":   0,
                    "error":              str(e)
                })

        # 7. Log valid findings to JSONL
        for finding in all_findings:
            log_event(
                event_type="accusation",
                agent="auditor_general",
                branch="judicial",
                payload=finding,
                session_id=current_session,
                articles=[finding.get("article", "Unknown")]
            )

        # 8. Write research log and enriched summary
        total_rejected = sum(len(b.get("rejected_findings", [])) for b in batch_records)
        total_errors   = sum(1 for b in batch_records if b.get("error"))

        research_path = write_research_log(
            session_id=current_session,
            timestamp=session_timestamp,
            config=CONFIG,
            mdns_count=len(mdns_data),
            device_count=len(raw_devices),
            batches=batch_records,
            all_findings=all_findings
        )

        summary_path = write_summary_file(
            session_id=current_session,
            timestamp=session_timestamp,
            cpu_temp_min_c=min(
                (b.get("cpu_temp_c") for b in batch_records
                 if b.get("cpu_temp_c") is not None), default=None
            ),
            cpu_temp_max_c=max(
                (b.get("cpu_temp_c") for b in batch_records
                 if b.get("cpu_temp_c") is not None), default=None
            ),
            device_count=len(raw_devices),
            mdns_count=len(mdns_data),
            all_findings=all_findings,
            rejected_count=total_rejected,
            error_count=total_errors,
            total_tokens=sum(
                b.get("tokens", {}).get("total_tokens", 0) for b in batch_records
        ),
        tokens_per_finding=(
            round(sum(b.get("tokens", {}).get("total_tokens", 0)
                for b in batch_records) / len(all_findings), 1)
            if all_findings else None
        ),
        seconds_per_finding=(
            round(sum(b.get("duration_seconds", 0)
            for b in batch_records) / len(all_findings), 2)
            if all_findings else None
        ),
)

        print(ct.paint(f"[-] Research log: {research_path}", ct.GREEN))
        print(ct.paint(f"[-] Summary:      {summary_path}", ct.GREEN))

    except Exception as e:
        print(ct.paint(f"[!] Critical Substrate Failure: {e}", ct.RED))

    finally:
        summarize_session(CONFIG["log_path"], current_session)
        print(f"SESSION_ID={current_session}")


if __name__ == "__main__":
    main()
