#!/bin/bash

# Batch script to run start_patching_loop.py with multiple POC files
# Usage: ./batch_patching.sh -a /path/to/app -p prefix [-n number]

set -e

# Default values
APP_PATH=""
PREFIX=""
N_PARAM=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POCES_DIR="${SCRIPT_DIR}/poces"
LOG_DIR="/p/tmp"

# Function to show usage
usage() {
    echo "Usage: $0 -a <app_path> -p <prefix> [-n <number>]"
    echo ""
    echo "Options:"
    echo "  -a <app_path>    Path to the application directory"
    echo "  -p <prefix>      Prefix of POC files to execute (e.g., 'hospital', 'joomla')"
    echo "  -n <number>      Number parameter to pass to start_patching_loop.py (optional)"
    echo "  -h               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -a /app/hospital -p hospital"
    echo "  $0 -a /app/hospital -p hospital -n 5"
    echo "  $0 -a /app/joomla -p joomla -n 10"
    echo ""
    echo "This script will:"
    echo "1. Find all POC files starting with <prefix> in ${POCES_DIR}"
    echo "2. Execute start_patching_loop.py for each POC file"
    echo "3. Pass -n parameter to start_patching_loop.py if specified"
    echo "4. Save logs to ${LOG_DIR}/<prefix>_<timestamp>.log"
    exit 1
}

# Parse command line arguments
while getopts "a:p:n:h" opt; do
    case ${opt} in
        a )
            APP_PATH="$OPTARG"
            ;;
        p )
            PREFIX="$OPTARG"
            ;;
        n )
            N_PARAM="$OPTARG"
            ;;
        h )
            usage
            ;;
        \? )
            echo "Invalid option: $OPTARG" 1>&2
            usage
            ;;
        : )
            echo "Invalid option: $OPTARG requires an argument" 1>&2
            usage
            ;;
    esac
done

# Check if required arguments are provided
if [[ -z "$APP_PATH" ]]; then
    echo "Error: Application path (-a) is required"
    usage
fi

if [[ -z "$PREFIX" ]]; then
    echo "Error: Prefix (-p) is required"
    usage
fi

# Validate application path
if [[ ! -d "$APP_PATH" ]]; then
    echo "Error: Application path '$APP_PATH' does not exist or is not a directory"
    exit 1
fi

# Validate POC directory
if [[ ! -d "$POCES_DIR" ]]; then
    echo "Error: POC directory '$POCES_DIR' does not exist"
    exit 1
fi

# Create log directory if it doesn't exist
if [[ ! -d "$LOG_DIR" ]]; then
    echo "Creating log directory: $LOG_DIR"
    mkdir -p "$LOG_DIR"
fi

# Find all POC files with the specified prefix
POC_FILES=($(find "$POCES_DIR" -name "${PREFIX}*.py" -type f | sort))

if [[ ${#POC_FILES[@]} -eq 0 ]]; then
    echo "Error: No POC files found with prefix '$PREFIX' in $POCES_DIR"
    echo "Looking for files matching pattern: ${PREFIX}*.py"
    exit 1
fi

echo "Found ${#POC_FILES[@]} POC files with prefix '$PREFIX':"
for poc_file in "${POC_FILES[@]}"; do
    echo "  - $(basename "$poc_file")"
done
echo ""

# Generate timestamp for log file
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/ABL0-${PREFIX}_${TIMESTAMP}.log"

echo "Starting batch execution..."
echo "Application path: $APP_PATH"
if [[ -n "$N_PARAM" ]]; then
    echo "N parameter: $N_PARAM"
fi
echo "Log file: $LOG_FILE"
echo "========================================"
echo ""

# Initialize log file
{
    echo "Batch Patching Execution Log"
    echo "Started at: $(date)"
    echo "Application path: $APP_PATH"
    echo "Prefix: $PREFIX"
    if [[ -n "$N_PARAM" ]]; then
        echo "N parameter: $N_PARAM"
    fi
    echo "Found ${#POC_FILES[@]} POC files"
    echo "========================================"
    echo ""
} > "$LOG_FILE"

# Counter for tracking progress
TOTAL_COUNT=${#POC_FILES[@]}
CURRENT_COUNT=0
SUCCESS_COUNT=0
FAILED_COUNT=0

# Execute start_patching_loop.py for each POC file
for poc_file in "${POC_FILES[@]}"; do
    # Only execute chmod if app path doesn't start with /app/phpmyadmin
    if [[ ! "$APP_PATH" =~ ^/app/phpmyadmin ]]; then
        sudo chmod -R 777 /app
    fi
    CURRENT_COUNT=$((CURRENT_COUNT + 1))
    POC_BASENAME=$(basename "$poc_file")
    POC_RELATIVE_PATH="poces/$POC_BASENAME"
    
    echo "[$CURRENT_COUNT/$TOTAL_COUNT] Processing: $POC_BASENAME"
    
    # Construct the command with optional -n parameter
    if [[ -n "$N_PARAM" ]]; then
        COMMAND="python3.8 start_patching_loop.py -a \"$APP_PATH\" -p \"$POC_RELATIVE_PATH\" -r -n \"$N_PARAM\""
    else
        COMMAND="python3.8 start_patching_loop.py -a \"$APP_PATH\" -p \"$POC_RELATIVE_PATH\" -r"
    fi
    
    # Log the start of this POC execution
    {
        echo "========================================"
        echo "[$CURRENT_COUNT/$TOTAL_COUNT] Processing: $POC_BASENAME"
        echo "Started at: $(date)"
        echo "Command: $COMMAND"
        echo "========================================"
    } >> "$LOG_FILE"
    
    # Execute the command and capture output
    START_TIME=$(date +%s)
    if [[ -n "$N_PARAM" ]]; then
        if python3.8 start_patching_loop.py -a "$APP_PATH" -p "$POC_RELATIVE_PATH" -r -n "$N_PARAM" >> "$LOG_FILE" 2>&1; then
            EXECUTION_SUCCESS=true
        else
            EXECUTION_SUCCESS=false
        fi
    else
        if python3.8 start_patching_loop.py -a "$APP_PATH" -p "$POC_RELATIVE_PATH" -r >> "$LOG_FILE" 2>&1; then
            EXECUTION_SUCCESS=true
        else
            EXECUTION_SUCCESS=false
        fi
    fi
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    if [[ "$EXECUTION_SUCCESS" == "true" ]]; then
        echo "  ✓ SUCCESS (${DURATION}s)"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        
        {
            echo ""
            echo "Duration: ${DURATION} seconds"
            echo "Completed at: $(date)"
            echo ""
        } >> "$LOG_FILE"
    else
        echo "  ✗ FAILED (${DURATION}s)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        
        {
            echo ""
            echo "Duration: ${DURATION} seconds"
            echo "Completed at: $(date)"
            echo ""
        } >> "$LOG_FILE"
    fi
done

# Final summary
echo ""
echo "========================================"
echo "Batch execution completed!"
echo "Total POCs processed: $TOTAL_COUNT"
echo "Successful: $SUCCESS_COUNT"
echo "Failed: $FAILED_COUNT"
echo "Log file: $LOG_FILE"
echo "========================================"

# Append summary to log file
{
    echo "========================================"
    echo "BATCH EXECUTION SUMMARY"
    echo "Completed at: $(date)"
    echo "Total POCs processed: $TOTAL_COUNT"
    echo "Finished: $SUCCESS_COUNT"
    echo "Errors: $FAILED_COUNT"
    echo "========================================"
} >> "$LOG_FILE"

# Exit with appropriate code
if [[ $FAILED_COUNT -eq 0 ]]; then
    echo "All POCs executed successfully!"
    exit 0
else
    echo "Some POCs failed. Check the log file for details."
    exit 1
fi