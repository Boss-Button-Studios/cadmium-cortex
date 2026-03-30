#!/usr/bin/env python3
"""
CC-Lite Audit Log Extractor
============================
Walks a directory tree and produces two CSV files:

  sessions.csv  — one row per session: aggregate metrics, hardware/config,
                  token counts, and efficiency metrics
  findings.csv  — one row per finding: full detail for qualitative analysis

Handles two source formats automatically:

  research_*.json   — rich per-session format (primary; preferred for analysis)
                      includes hardware, config, timing, token counts, rejected
                      findings, and pre-computed efficiency metrics
  audit.jsonl       — operational Section 9 log (fallback; used if no research
                      JSON files are found in a folder)

Organise runs as condition subfolders — the folder name becomes the condition label:

  data/
    baseline/
      research_2026-03-29T00-01-54.json
    temperature_0.2/
      research_2026-03-29T02-30-00.json
    mininet_scenario_A/
      research_2026-03-29T03-00-00.json
      ground_truth.json   <- optional; enables TP/FP/FN columns

ground_truth.json schema (Mininet use):
  {
    "violations": [
      { "device_id": "aabbccddeeff", "article": "IV" },
      ...
    ]
  }

Usage:
  python3 extract_results.py <root_dir> [--out <output_dir>]
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict

# --- Constants ----------------------------------------------------------------

ARTICLES         = ["I", "II", "III", "IV", "V"]
SUSPICION_LEVELS = ["low", "medium", "high"]

# --- Ground truth -------------------------------------------------------------

def load_ground_truth(folder: str):
    gt_path = os.path.join(folder, "ground_truth.json")
    if not os.path.exists(gt_path):
        return None
    with open(gt_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        (v["device_id"].replace(":", "").lower(), v["article"].upper())
        for v in data.get("violations", [])
    }

# --- File discovery -----------------------------------------------------------

def find_source_files(root: str) -> list:
    by_folder = defaultdict(lambda: {"research": [], "jsonl": []})
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if fname.startswith("research_") and fname.endswith(".json"):
                by_folder[dirpath]["research"].append(fpath)
            elif fname.endswith(".jsonl"):
                by_folder[dirpath]["jsonl"].append(fpath)

    results = []
    for dirpath, files in sorted(by_folder.items()):
        rel       = os.path.relpath(dirpath, root)
        condition = rel if rel != "." else "root"
        if files["research"]:
            for fpath in sorted(files["research"]):
                results.append((condition, dirpath, fpath, "research"))
        elif files["jsonl"]:
            for fpath in sorted(files["jsonl"]):
                results.append((condition, dirpath, fpath, "jsonl"))
    return results

# --- Shared helpers -----------------------------------------------------------

def evaluate_ground_truth(finding_rows: list, ground_truth) -> tuple:
    if ground_truth is None:
        return "", "", ""
    tp = 0
    fp = 0
    found = set()
    for f in finding_rows:
        did = f["device_id"].replace(":", "").lower()
        art = f["article"].strip().upper()
        if (did, art) in ground_truth:
            tp += 1
            found.add((did, art))
            f["is_true_positive"]  = True
            f["is_false_positive"] = False
        else:
            fp += 1
            f["is_true_positive"]  = False
            f["is_false_positive"] = True
    fn = len(ground_truth - found)
    return tp, fp, fn


def count_findings(finding_rows: list) -> tuple:
    article_counts   = {f"findings_article_{a}": 0 for a in ARTICLES}
    suspicion_counts = {f"findings_{s}": 0 for s in SUSPICION_LEVELS}
    for f in finding_rows:
        a_key = f"findings_article_{f['article'].strip().upper()}"
        s_key = f"findings_{f['suspicion_level'].strip().lower()}"
        if a_key in article_counts:
            article_counts[a_key] += 1
        if s_key in suspicion_counts:
            suspicion_counts[s_key] += 1
    return article_counts, suspicion_counts

# --- Research JSON extraction -------------------------------------------------

def extract_research_json(file_path: str, condition: str, ground_truth) -> tuple:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    sid       = data.get("session_id", "")
    timestamp = data.get("timestamp", "")
    hw        = data.get("hardware", {})
    cfg       = data.get("config", {})
    census    = data.get("census", {})
    summary   = data.get("summary", {})

    finding_rows = []
    for finding in data.get("valid_findings", []):
        finding_rows.append({
            "session_id":        sid,
            "condition":         condition,
            "source_file":       os.path.basename(file_path),
            "timestamp":         timestamp,
            "device_id":         finding.get("device_id", ""),
            "article":           finding.get("article", ""),
            "suspicion_level":   finding.get("suspicion_level", ""),
            "evidence":          finding.get("evidence", ""),
            "reasoning":         finding.get("reasoning", ""),
            "is_true_positive":  "",
            "is_false_positive": "",
        })

    article_counts, suspicion_counts = count_findings(finding_rows)
    tp, fp, fn = evaluate_ground_truth(finding_rows, ground_truth)

    session_row = {
        "session_id":              sid,
        "condition":               condition,
        "source_file":             os.path.basename(file_path),
        "timestamp":               timestamp,
        # Hardware
        "platform":                hw.get("platform", ""),
        "python_version":          hw.get("python_version", ""),
        "cpu_cores":               hw.get("cpu_cores", ""),
        "ram_gb":                  hw.get("ram_gb", ""),
        # Config
        "model":                   cfg.get("model", ""),
        "temperature":             cfg.get("temperature", ""),
        "num_ctx":                 cfg.get("num_ctx", ""),
        "num_gpu":                 cfg.get("num_gpu", ""),
        "batch_size":              cfg.get("batch_size", ""),
        # Census
        "device_count":            census.get("device_count", ""),
        "mdns_responses":          census.get("mdns_responses", ""),
        # Run summary
        "total_batches":           summary.get("total_batches", ""),
        "total_valid_findings":    summary.get("total_valid_findings", ""),
        "total_rejected_findings": summary.get("total_rejected_findings", ""),
        "total_errors":            summary.get("total_errors", ""),
        "total_inference_seconds": summary.get("total_inference_seconds", ""),
        # Token counts
        "total_prompt_tokens":     summary.get("total_prompt_tokens", ""),
        "total_completion_tokens": summary.get("total_completion_tokens", ""),
        "total_tokens":            summary.get("total_tokens", ""),
        # Efficiency metrics
        "tokens_per_finding":      summary.get("tokens_per_finding", ""),
        "seconds_per_finding":     summary.get("seconds_per_finding", ""),
        "rejection_rate":          summary.get("rejection_rate", ""),
        # Finding breakdowns
        **article_counts,
        **suspicion_counts,
        # Ground truth
        "true_positives":          tp,
        "false_positives":         fp,
        "false_negatives":         fn,
    }

    return [session_row], finding_rows

# --- JSONL fallback extraction ------------------------------------------------

def iter_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  [!] Skipped malformed line {lineno} in {path}: {e}",
                      file=sys.stderr)


def extract_jsonl(file_path: str, condition: str, ground_truth) -> tuple:
    sessions            = {}
    findings_by_session = defaultdict(list)

    for event in iter_jsonl(file_path):
        sid = event.get("session_id")
        if not sid:
            continue
        if sid not in sessions:
            sessions[sid] = {
                "session_id":   sid,
                "condition":    condition,
                "source_file":  os.path.basename(file_path),
                "timestamp":    event.get("timestamp", ""),
                "device_count": 0,
            }
        ts = event.get("timestamp", "")
        if ts and ts < sessions[sid]["timestamp"]:
            sessions[sid]["timestamp"] = ts
        if event.get("event_type") == "observation":
            sessions[sid]["device_count"] += 1
        if (event.get("agent") == "auditor_general" and
                event.get("event_type") == "accusation"):
            payload = event.get("payload", {})
            findings_by_session[sid].append({
                "session_id":        sid,
                "condition":         condition,
                "source_file":       os.path.basename(file_path),
                "timestamp":         event.get("timestamp", ""),
                "device_id":         payload.get("device_id", ""),
                "article":           payload.get("article", ""),
                "suspicion_level":   payload.get("suspicion_level", ""),
                "evidence":          payload.get("evidence", ""),
                "reasoning":         payload.get("reasoning", ""),
                "is_true_positive":  "",
                "is_false_positive": "",
            })

    session_rows = []
    finding_rows = []

    for sid, meta in sessions.items():
        flist = findings_by_session.get(sid, [])
        article_counts, suspicion_counts = count_findings(flist)
        tp, fp, fn = evaluate_ground_truth(flist, ground_truth)

        # Token columns blank for JSONL — not captured in that format
        session_rows.append({
            "session_id":              sid,
            "condition":               condition,
            "source_file":             meta["source_file"],
            "timestamp":               meta["timestamp"],
            "platform":                "",
            "python_version":          "",
            "cpu_cores":               "",
            "ram_gb":                  "",
            "model":                   "",
            "temperature":             "",
            "num_ctx":                 "",
            "num_gpu":                 "",
            "batch_size":              "",
            "device_count":            meta["device_count"],
            "mdns_responses":          "",
            "total_batches":           "",
            "total_valid_findings":    len(flist),
            "total_rejected_findings": "",
            "total_errors":            "",
            "total_inference_seconds": "",
            "total_prompt_tokens":     "",
            "total_completion_tokens": "",
            "total_tokens":            "",
            "tokens_per_finding":      "",
            "seconds_per_finding":     "",
            "rejection_rate":          "",
            **article_counts,
            **suspicion_counts,
            "true_positives":          tp,
            "false_positives":         fp,
            "false_negatives":         fn,
        })
        finding_rows.extend(flist)

    return session_rows, finding_rows

# --- CSV output ---------------------------------------------------------------

SESSION_FIELDS = [
    "session_id", "condition", "source_file", "timestamp",
    # Hardware
    "platform", "python_version", "cpu_cores", "ram_gb",
    # Config
    "model", "temperature", "num_ctx", "num_gpu", "batch_size",
    # Census
    "device_count", "mdns_responses",
    # Run summary
    "total_batches", "total_valid_findings", "total_rejected_findings",
    "total_errors", "total_inference_seconds",
    # Tokens
    "total_prompt_tokens", "total_completion_tokens", "total_tokens",
    # Efficiency
    "tokens_per_finding", "seconds_per_finding", "rejection_rate",
    # Finding breakdowns
    *[f"findings_article_{a}" for a in ARTICLES],
    *[f"findings_{s}" for s in SUSPICION_LEVELS],
    # Ground truth
    "true_positives", "false_positives", "false_negatives",
]

FINDING_FIELDS = [
    "session_id", "condition", "source_file", "timestamp",
    "device_id", "article", "suspicion_level",
    "evidence", "reasoning",
    "is_true_positive", "is_false_positive",
]


def write_csv(path: str, rows: list, fields: list) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Written: {path} ({len(rows)} rows)")

# --- Entry point --------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract CC-Lite audit results to CSV for analysis."
    )
    parser.add_argument("root_dir",
                        help="Root directory containing condition subfolders")
    parser.add_argument("--out", default=None,
                        help="Output directory for CSV files (default: root_dir)")
    args = parser.parse_args()

    root    = os.path.abspath(args.root_dir)
    out_dir = os.path.abspath(args.out) if args.out else root

    if not os.path.isdir(root):
        print(f"[!] Not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)

    source_files = find_source_files(root)
    if not source_files:
        print(f"[!] No research JSON or JSONL files found under {root}",
              file=sys.stderr)
        sys.exit(1)

    conditions = set(c for c, _, _, _ in source_files)
    print(f"Found {len(source_files)} source file(s) across "
          f"{len(conditions)} condition(s).\n")

    all_sessions = []
    all_findings = []

    for condition, folder, file_path, fmt in source_files:
        gt       = load_ground_truth(folder)
        gt_label = "with ground truth" if gt is not None else "no ground truth"
        print(f"[{condition}] {os.path.basename(file_path)} ({fmt}, {gt_label})")

        if fmt == "research":
            s_rows, f_rows = extract_research_json(file_path, condition, gt)
        else:
            s_rows, f_rows = extract_jsonl(file_path, condition, gt)

        print(f"  {len(s_rows)} session(s), {len(f_rows)} finding(s)")
        all_sessions.extend(s_rows)
        all_findings.extend(f_rows)

    print()
    write_csv(os.path.join(out_dir, "sessions.csv"), all_sessions, SESSION_FIELDS)
    write_csv(os.path.join(out_dir, "findings.csv"), all_findings, FINDING_FIELDS)
    print("\nDone.")


if __name__ == "__main__":
    main()
