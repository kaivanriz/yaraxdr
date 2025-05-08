#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) SOCFortress, LLP.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo "$INPUT_JSON" | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo "$INPUT_JSON" | jq -r .parameters.extra_args[3])
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)
QUARANTINE_PATH="/tmp/quarantined"
LOG_FILE="/var/ossec/logs/active-responses.log"

# Logging function
log_message() {
    echo "wazuh-yara: $(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Create QUARANTINE_PATH if it does not exist
mkdir -p "$QUARANTINE_PATH" || {
    log_message "ERROR - Failed to create quarantine directory: $QUARANTINE_PATH"
    exit 1
}
chown root:root "$QUARANTINE_PATH"
chmod 700 "$QUARANTINE_PATH"

#----------------------- Analyze parameters -----------------------#

if [[ ! "$YARA_PATH" ]] || [[ ! "$YARA_RULES" ]]; then
    log_message "ERROR - Yara path and rules parameters are mandatory."
    exit 1
fi

if [[ ! -x "$YARA_PATH" ]]; then
    log_message "ERROR - Yara binary not executable: $YARA_PATH"
    exit 1
fi

if [[ ! -f "$YARA_RULES" ]]; then
    log_message "ERROR - Yara rules file not found: $YARA_RULES"
    exit 1
fi

# Wait for file size to stabilize with timeout
size=0
actual_size=$(stat -c %s "$FILENAME" 2>/dev/null || echo 0)
timeout=30
elapsed=0
while [ "$size" -ne "$actual_size" ] && [ "$elapsed" -lt "$timeout" ]; do
    sleep 1
    size="$actual_size"
    actual_size=$(stat -c %s "$FILENAME" 2>/dev/null || echo 0)
    elapsed=$((elapsed + 1))
done
if [ "$elapsed" -ge "$timeout" ]; then
    log_message "ERROR - Timeout waiting for file size stabilization: $FILENAME"
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute Yara scan
yara_output="$("$YARA_PATH" -C -w -r -f -m "$YARA_RULES" "$FILENAME" 2>&1)"
if [[ $? -ne 0 ]]; then
    log_message "WARNING - Yara scan failed: $yara_output"
    exit 1
fi

if [[ -n "$yara_output" ]]; then
    # Log each detected rule
    while read -r line; do
        log_message "ALERT - Scan result: $line"
    done <<< "$yara_output"

    # Quarantine the file
    FILEBASE=$(basename "$FILENAME")
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    NEW_FILENAME="${TIMESTAMP}_${FILEBASE}"
    mv -f "$FILENAME" "${QUARANTINE_PATH}/${NEW_FILENAME}" || {
        log_message "ERROR - Failed to move $FILENAME to ${QUARANTINE_PATH}/${NEW_FILENAME}"
        exit 1
    }
    chattr -R +i "${QUARANTINE_PATH}/${NEW_FILENAME}" || {
        log_message "WARNING - Failed to set immutable attribute on ${QUARANTINE_PATH}/${NEW_FILENAME}"
    }
    log_message "INFO - $FILENAME moved to ${QUARANTINE_PATH}/${NEW_FILENAME}"
fi

exit 0