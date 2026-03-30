#!/bin/bash
# $1: Total Audit Cycles
# $2: Cool-down Period (Seconds)

if [ $# -lt 2 ]; then
    echo "Usage: $0 <cycles> <cool_down>"
    exit 1
fi

LOG_FILE="research_run_$(date +%Y%m%d_%H%M%S).log"
echo "Beginning $1 cycles. Monitoring drift in $LOG_FILE"

for ((i=1; i<=$1; i++)); do
    START_TIME=$(date +%s)
    echo "=== CYCLE $i/$1 STARTING AT $(date +%H:%M:%S) ===" | tee -a "$LOG_FILE"
    
    # Run the audit
    ./run_audit.sh
    
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    
    echo "=== CYCLE $i COMPLETE. Duration: ${ELAPSED}s ===" | tee -a "$LOG_FILE"
    
    # Capture current CPU Package Temp
    CPU_TEMP=$(cat /sys/class/thermal/thermal_zone8/temp)
    CPU_C=$((CPU_TEMP / 1000))

    echo "Current Substrate Temp: ${CPU_C}°C"

    # Example: If temp is too high, double the sleep time
    if [ $CPU_C -gt 75 ]; then
        echo "Warning: Thermal Saturation detected. Increasing rest period."
        sleep $(( $2 * 2 ))
    fi

    if [ $i -lt $1 ]; then
        echo "Dissipating heat for $2 seconds..."
        sleep $2
    fi
    
    # Keep the sudo ticket alive
    sudo -v
done

echo "Research batch complete."
