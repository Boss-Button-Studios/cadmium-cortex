#!/bin/bash
for i in {1..100}; do
    echo "=== RUN $i/100 ==="
    ./run_audit.sh
    echo ""
    sleep 60
    sudo -v
done
