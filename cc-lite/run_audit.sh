#!/bin/bash

#Clear old Python compiled files
find . -name "__pycache__" -type d -exec rm -rf {} +

# --- CONFIGURATION ---
LOG_FILE="audit/audit.jsonl"
ROUTER_IP="192.168.0.1"
ADMIN_MAC="90:09:d0:xx:xx:xx" 

echo "--- [1/4] RESETTING OLLAMA SUBSTRATE ---"
sudo pkill -9 ollama
sudo systemctl restart ollama
sleep 5

echo "--- [2/4] EXPANDING LEGISLATIVE CENSUS (Ping Sweep) ---"
for i in {1..254}; do 
    ping -c 1 -W 1 192.168.0.$i > /dev/null 2>&1 & 
done
wait
echo "Census expansion complete."

echo "--- [3/4] EXECUTING CONSTITUTIONAL AUDIT ---"
AUDIT_OUTPUT=$(OLLAMA_NUM_PARALLEL=1 CUDA_VISIBLE_DEVICES="" python3 main.py)
echo "$AUDIT_OUTPUT"
LATEST_SESSION=$(echo "$AUDIT_OUTPUT" | grep "^SESSION_ID=" | cut -d= -f2)

echo "--- [4/4] JUDICIAL SUMMARY (Session: $LATEST_SESSION) ---"
if [ -z "$LATEST_SESSION" ]; then
    echo "[!] No session ID captured — audit may have failed entirely."
else
    grep "$LATEST_SESSION" "$LOG_FILE" | grep "auditor_general" | \
        jq -r '.payload | "[\(.article)] \(.suspicion_level): \(.evidence)"'
fi

echo "------------------------------------------"
