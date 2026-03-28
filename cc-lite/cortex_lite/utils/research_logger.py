import json
import os
import platform
import logging
from datetime import datetime, timezone


def _hardware_context() -> dict:
    """Collects basic hardware info using stdlib only."""
    context = {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "python_version": platform.python_version(),
        "cpu_cores": os.cpu_count(),
        "ram_gb": None
    }

    # Read RAM from /proc/meminfo on Linux
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


def write_research_log(
    session_id: str,
    timestamp: str,
    config: dict,
    mdns_count: int,
    device_count: int,
    batches: list,
    all_findings: list,
    output_dir: str = "audit/summary"
) -> str:
    """
    Writes a per-session research JSON log.

    batches: list of dicts returned by AuditorGeneral.audit(), each augmented
             with 'batch_index' and 'batch_device_count' by the caller.

    Returns the path of the written file.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Sanitize timestamp for filename
    ts_safe = timestamp.replace(":", "-").replace(" ", "_")[:19]
    path = os.path.join(output_dir, f"research_{ts_safe}.json")

    total_rejected = sum(len(b.get("rejected_findings", [])) for b in batches)
    total_errors   = sum(1 for b in batches if b.get("error"))
    total_duration = round(sum(b.get("duration_seconds", 0) for b in batches), 2)

    record = {
        "session_id": session_id,
        "timestamp": timestamp,
        "hardware": _hardware_context(),
        "config": {
            "model": config.get("model"),
            "gateway_ip": config.get("gateway_ip"),
            "batch_size": config.get("batch_size", 4),
            "num_gpu": 0,
            "temperature": 0.2,
            "num_ctx": 2048
        },
        "census": {
            "device_count": device_count,
            "mdns_responses": mdns_count
        },
        "summary": {
            "total_batches": len(batches),
            "total_valid_findings": len(all_findings),
            "total_rejected_findings": total_rejected,
            "total_errors": total_errors,
            "total_inference_seconds": total_duration
        },
        "batches": batches,
        "valid_findings": all_findings
    }

    try:
        with open(path, "w") as f:
            json.dump(record, f, indent=2)
        logging.info(f"Research log written to {path}")
    except Exception as e:
        logging.error(f"Failed to write research log: {e}")

    return path


def write_summary_file(
    session_id: str,
    timestamp: str,
    device_count: int,
    mdns_count: int,
    all_findings: list,
    rejected_count: int,
    error_count: int,
    output_dir: str = "audit/summary"
) -> str:
    """
    Writes a human-readable plain-text summary file.
    Returns the path of the written file.
    """
    os.makedirs(output_dir, exist_ok=True)

    ts_safe = timestamp.replace(":", "-").replace(" ", "_")[:19]
    path = os.path.join(output_dir, f"summary_{ts_safe}.txt")

    lines = [
        "=" * 60,
        f"CONSTITUTIONAL AUDIT SUMMARY",
        f"Session : {session_id}",
        f"Generated: {timestamp}",
        f"Devices  : {device_count} observed, {mdns_count} resolved via mDNS",
        f"Findings : {len(all_findings)} valid | {rejected_count} rejected | {error_count} batch errors",
        "=" * 60,
        ""
    ]

    if not all_findings:
        lines.append("No violations found.")
    else:
        by_article = {}
        for f in all_findings:
            art = f.get("article", "?")
            by_article.setdefault(art, []).append(f)

        for art in sorted(by_article.keys()):
            lines.append(f"--- Article {art} ---")
            for f in by_article[art]:
                level    = f.get("suspicion_level", "?").upper()
                device   = f.get("device_id", "?")
                hostname = f.get("hostname") or ""
                label    = f"{hostname} ({device})" if hostname else device
                evidence = f.get("evidence", "")
                lines.append(f"  [{level}] {label}")
                lines.append(f"  {evidence}")
                lines.append("")

    try:
        with open(path, "w") as f:
            f.write("\n".join(lines))
        logging.info(f"Summary written to {path}")
    except Exception as e:
        logging.error(f"Failed to write summary: {e}")

    return path
