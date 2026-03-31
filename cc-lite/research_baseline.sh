#!/bin/bash

# ==============================================================================
# CC-LITE RESEARCH BASELINE: SUBSTRATE STRESSER V2
# ==============================================================================
# DESCRIPTION:
#   Manages thermal dissipation to observe "Thermal-Induced Stochastic Drift."
#   PRIORITY: Fever Mode (-q/-s) now overrides the 90°C Safety Gate.
# SYNTAX:
#   ./research_baseline.sh [runs] [rest] [-f] [-q value] [-s value]
#
# ARGUMENTS:
#   [runs]      : Total number of audit cycles to perform (N=30 recommended).
#   [rest]      : Normal cooldown period (seconds) to maintain stable substrate.
#
# FLAGS:
#   -f          : Enables "Intermittent Fever" using internal defaults.
#   -q [value]  : Frequency. Triggers a short rest every [value] runs.
#   -s [value]  : Intensity. Sets the short rest to [value] seconds.
#
# LOGIC MODES:
#   1. Healthy (Default): Uses [rest] and doubles it if CPU > 75°C.
#   2. Fever (Flags): Overrides safety; pulses heat by using [s] every [q] runs.
# ==============================================================================

# --- Defensive Argument Parsing ---
# Strips leading hyphens from positional arguments if present
RUNS_RAW=$1
REST_RAW=$2
CYCLES=${RUNS_RAW#-}
NORMAL_REST=${REST_RAW#-}

if [ -z "$CYCLES" ] || [ -z "$NORMAL_REST" ]; then
    echo "Usage: $0 <runs> <rest_secs> [-f] [-q freq] [-s short_rest]"
    exit 1
fi

# Default Fever Settings
FEVER_MODE=0
SHORT_CYCLE_FREQ=5  
SHORT_REST_VAL=0    

shift 2 

while getopts "fq:s:" opt; do
  case $opt in
    f) FEVER_MODE=1 ;;
    q) SHORT_CYCLE_FREQ=$OPTARG; FEVER_MODE=1 ;;
    s) SHORT_REST_VAL=$OPTARG; FEVER_MODE=1 ;;
    *) exit 1 ;;
  esac
done

# Set default short rest (1/4 of normal) if not specified
if [ $FEVER_MODE -eq 1 ] && [ $SHORT_REST_VAL -eq 0 ]; then
    SHORT_REST_VAL=$(( NORMAL_REST / 4 ))
fi

LOG_FILE="research_run_$(date +%Y%m%d_%H%M%S).log"
echo "BATCH START: $CYCLES runs | Baseline Rest: ${NORMAL_REST}s" | tee -a "$LOG_FILE"
if [ $FEVER_MODE -eq 1 ]; then
    echo "STRESS PROFILE: Short rest (${SHORT_REST_VAL}s) every ${SHORT_CYCLE_FREQ} runs." | tee -a "$LOG_FILE"
fi

# --- Main Execution Loop ---

for ((i=1; i<=CYCLES; i++)); do
    CPU_START=$(($(cat /sys/class/thermal/thermal_zone8/temp) / 1000))
    echo "------------------------------------------------" | tee -a "$LOG_FILE"
    echo "RUN $i/$CYCLES | START TEMP: ${CPU_START}°C" | tee -a "$LOG_FILE"
    
    ./run_audit.sh
    
    CPU_END=$(($(cat /sys/class/thermal/thermal_zone8/temp) / 1000))
    
    if [ $i -lt $CYCLES ]; then
        # 1. PRIORITY: Fever Trigger (The Experiment)
        if [ $FEVER_MODE -eq 1 ] && [ $(( i % SHORT_CYCLE_FREQ )) -eq 0 ]; then
            echo "!!! FEVER TRIGGERED (Run $i) !!! Overriding safety." | tee -a "$LOG_FILE"
            echo "Resting only ${SHORT_REST_VAL}s..." | tee -a "$LOG_FILE"
            sleep $SHORT_REST_VAL
            
        # 2. SECONDARY: Safety Gate (Hardware Protection)
        elif [ $CPU_END -gt 90 ]; then
            SLEEP_VAL=$(( NORMAL_REST * 2 ))
            echo "CRITICAL HEAT ($CPU_END°C). Safety Gate Active. Rest: ${SLEEP_VAL}s" | tee -a "$LOG_FILE"
            sleep $SLEEP_VAL
            
        # 3. TERTIARY: Standard Operation
        else
            echo "Standard Rest: ${NORMAL_REST}s" | tee -a "$LOG_FILE"
            sleep $NORMAL_REST
        fi
    fi
done

echo "Batch complete. Substrate state logged."
