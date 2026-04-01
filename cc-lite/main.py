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
from cortex_lite.census.oui_lookup import OUILookup
from cortex_lite.census.census_agent import build_dossiers, load_router_labels
from cortex_lite.auditor.constitution_loader import load_constitution
from cortex_lite.auditor.auditor_general import AuditorGeneral
from cortex_lite.utils.reporter import summarize_session
from cortex_lite.utils.research_logger import write_research_log, write_summary_file

# --- CONFIGURATION ---
CONFIG = {
    "admin_mac":      "90:09:d0:51:ed:f0",
    "gateway_ip":     "192.168.0.1",
    "model":          "llama3.2:3b",
    "log_path":       "audit/audit.jsonl",
    "batch_size":     4,
    "num_gpu":        0,
    "temperature":    0.2,
    "num_ctx":        2048,
    "oui_txt_path":   "data/oui.txt",
    "oui_csv_path":   "data/oui.csv",
    "router_labels":  "data/known_devices.csv",  # optional — skipped if absent
}


# --- SPINNER -----------------------------------------------------------------

class Spinner:
    def __init__(self, message):
        self.message  = message
        self._running = False
        self._thread  = None

    def __enter__(self):
        self._running = True
        self._thread  = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._running = False
        self._thread.join()
        sys.stderr.write('\r' + ' ' * (len(self.message) + 4) + '\r')
        sys.stderr.flush()

    def _spin(self):
        for char in itertools.cycle('|/-\\'):
            if not self._running:
                break
            sys.stderr.write(f'\r{self.message} {char}')
            sys.stderr.flush()
            time.sleep(0.1)


# --- THERMAL -----------------------------------------------------------------

def _read_cpu_temp() -> float | None:
    for zone in ["thermal_zone8", "thermal_zone1", "thermal_zone0"]:
        try:
            with open(f"/sys/class/thermal/{zone}/temp", "r") as f:
                candidate = round(int(f.read().strip()) / 1000, 1)
            if candidate > 30.0:
                return candidate
        except Exception:
            continue
    return None


# --- LOGGING -----------------------------------------------------------------

def log_event(event_type, agent, branch, payload, session_id, articles=None):
    """Writes a Section 9 compliant record to the JSONL audit log."""
    record = {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent":            agent,
        "branch":           branch,
        "event_type":       event_type,
        "session_id":       session_id,
        "articles_touched": articles or [],
        "payload":          payload,
    }
    os.makedirs(os.path.dirname(CONFIG["log_path"]), exist_ok=True)
    with open(CONFIG["log_path"], "a") as f:
        f.write(json.dumps(record) + "\n")


# --- CENSUS ------------------------------------------------------------------

class CensusTaker:
    def __init__(self, interface="wlp3s0", gateway_ip="192.168.0.1"):
        self.interface  = interface
        self.gateway_ip = gateway_ip

    def active_survey(self):
        """Ping sweep to populate ARP cache."""
        print(ct.paint("[*] Surveying network...", ct.YELLOW))
        subnet    = ".".join(self.gateway_ip.split('.')[:-1])
        processes = []
        for i in range(1, 255):
            p = subprocess.Popen(
                ["ping", "-c", "1", "-W", "1", f"{subnet}.{i}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            processes.append(p)
        for p in processes:
            p.wait()
        os.system("sleep 2")


# --- HARDWARE CONTEXT --------------------------------------------------------

def get_hardware_context() -> dict:
    import platform
    context = {
        "platform":         platform.system(),
        "platform_version": platform.version(),
        "python_version":   platform.python_version(),
        "cpu_cores":        os.cpu_count(),
        "ram_gb":           None,
    }
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    context["ram_gb"] = round(kb / (1024 ** 2), 1)
                    break
    except Exception:
        pass
    return context


# --- MAIN --------------------------------------------------------------------

def main():
    current_session   = str(uuid.uuid4())
    session_timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    hardware          = get_hardware_context()

    print(ct.paint(f"\n{ct.BOLD}CADMIUM CORTEX -- Constitutional Audit", ct.BLUE))
    print(ct.paint(f"Session: {current_session}\n", ct.BLUE))

    census = CensusTaker(interface="wlp3s0", gateway_ip=CONFIG["gateway_ip"])
    census.active_survey()

    try:
        # 1. Constitution
        const_text = load_constitution()
        print(ct.paint("[-] Constitution loaded and versioned.", ct.GREEN))

        # 2. OUI database
        oui_db = OUILookup(
            csv_path=CONFIG["oui_csv_path"],
            txt_path=CONFIG["oui_txt_path"],
        )
        print(ct.paint(
            f"[-] OUI database loaded ({len(oui_db.registry)} entries).", ct.GREEN
        ))

        # 3. Router labels (optional)
        router_labels = load_router_labels(CONFIG["router_labels"])
        if router_labels:
            print(ct.paint(
                f"[-] Router labels loaded ({len(router_labels)} entries).", ct.GREEN
            ))

        # 4. mDNS scan
        print(ct.paint("[*] Running mDNS scan...", ct.YELLOW))
        mdns_data = mdns_scan(listen_seconds=10)
        print(ct.paint(f"[-] mDNS returned {len(mdns_data)} device(s).", ct.GREEN))

        # 5. ARP census
        raw_devices = get_arp_table(interface=census.interface)
        print(ct.paint(f"[-] ARP census: {len(raw_devices)} live device(s).", ct.GREEN))

        # 6. Build dossiers — deterministic classification before LLM sees anything
        dossiers = build_dossiers(
            arp_entries   = raw_devices,
            mdns_data     = mdns_data,
            oui_lookup    = oui_db,
            admin_mac     = CONFIG["admin_mac"],
            gateway_ip    = CONFIG["gateway_ip"],
            router_labels = router_labels if router_labels else None,
        )

        # Print classification summary
        from collections import Counter
        class_counts = Counter(d.device_class for d in dossiers)
        summary_str  = " | ".join(f"{cls}: {n}" for cls, n in sorted(class_counts.items()))
        print(ct.paint(f"[-] Dossiers: {summary_str}", ct.GREEN))

        # Only IoT, Unknown, and Unknown-Random go to the auditor
        audit_targets = [
            d.to_audit_dict() for d in dossiers
            if d.device_class in {"IoT", "Unknown", "Unknown-Random"}
        ]
        print(ct.paint(
            f"[*] Auditor scope: {len(audit_targets)} device(s) "
            f"({len(dossiers) - len(audit_targets)} excluded by classification).",
            ct.YELLOW
        ))

        census_meta = {
            "device_count":    len(dossiers),
            "mdns_responses":  len(mdns_data),
            "audit_targets":   len(audit_targets),
            "class_counts":    dict(class_counts),
        }

        # 7. Judicial deliberation — only on audit targets
        auditor       = AuditorGeneral(CONFIG["model"], const_text)
        batch_size    = CONFIG["batch_size"]
        total_batches = max(1, -(-len(audit_targets) // batch_size))

        if not audit_targets:
            print(ct.paint("[+] No audit targets after classification. Clean network.", ct.GREEN))
            batch_records = []
            all_findings  = []
        else:
            print(ct.paint(
                f"[*] Auditor deliberating on {len(audit_targets)} device(s)...",
                ct.YELLOW
            ))

            batch_records = []
            all_findings  = []

            for i in range(0, len(audit_targets), batch_size):
                batch     = audit_targets[i: i + batch_size]
                batch_num = i // batch_size + 1
                msg       = ct.paint(
                    f"    > Batch {batch_num}/{total_batches} ({len(batch)} devices)",
                    ct.YELLOW
                )

                try:
                    time.sleep(1)
                    cpu_temp = _read_cpu_temp()
                    t_start  = time.time()

                    with Spinner(msg):
                        result = auditor.audit(
                            dossiers   = batch,
                            gateway_ip = CONFIG["gateway_ip"],
                            admin_id   = CONFIG["admin_mac"],
                        )

                    duration = round(time.time() - t_start, 2)

                    result["batch_index"]        = batch_num
                    result["batch_device_count"] = len(batch)
                    result["cpu_temp_c"]         = cpu_temp
                    batch_records.append(result)

                    if result["error"]:
                        print(ct.paint(
                            f"    [!] Batch {batch_num} error: {result['error']}", ct.RED
                        ))
                    elif result["valid_findings"]:
                        count = len(result["valid_findings"])
                        tok   = result["tokens"]
                        print(ct.paint(
                            f"      [+] {count} finding(s) | "
                            f"{tok['prompt_tokens']}p + {tok['completion_tokens']}c "
                            f"= {tok['total_tokens']} tokens",
                            ct.GREEN
                        ))
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
                        "tokens":             {"prompt_tokens": 0,
                                               "completion_tokens": 0,
                                               "total_tokens": 0},
                        "duration_seconds":   0,
                        "cpu_temp_c":         None,
                        "error":              str(e),
                    })

        # 8. Log findings to audit JSONL
        for finding in all_findings:
            log_event(
                event_type = "accusation",
                agent      = "auditor_general",
                branch     = "judicial",
                payload    = finding,
                session_id = current_session,
                articles   = [finding.get("article", "Unknown")],
            )

        # 9. Write research log and summary
        total_rejected = sum(len(b.get("rejected_findings", [])) for b in batch_records)
        total_errors   = sum(1 for b in batch_records if b.get("error"))
        total_tokens   = sum(b.get("tokens", {}).get("total_tokens", 0)
                             for b in batch_records)
        total_secs     = sum(b.get("duration_seconds", 0) for b in batch_records)

        research_path = write_research_log(
            session_id   = current_session,
            timestamp    = session_timestamp,
            config       = CONFIG,
            mdns_count   = len(mdns_data),
            device_count = len(dossiers),
            batches      = batch_records,
            all_findings = all_findings,
        )

        summary_path = write_summary_file(
            session_id          = current_session,
            timestamp           = session_timestamp,
            device_count        = len(dossiers),
            mdns_count          = len(mdns_data),
            all_findings        = all_findings,
            rejected_count      = total_rejected,
            error_count         = total_errors,
            total_tokens        = total_tokens,
            tokens_per_finding  = (
                round(total_tokens / len(all_findings), 1)
                if all_findings else None
            ),
            seconds_per_finding = (
                round(total_secs / len(all_findings), 2)
                if all_findings else None
            ),
            cpu_temp_min_c = min(
                (b["cpu_temp_c"] for b in batch_records
                 if b.get("cpu_temp_c") is not None), default=None
            ),
            cpu_temp_max_c = max(
                (b["cpu_temp_c"] for b in batch_records
                 if b.get("cpu_temp_c") is not None), default=None
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
