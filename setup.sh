#!/bin/bash
# Yara and Wazuh Active Response Setup Script with Cronjob Automation
# Copyright (C) TangerangKota-CSIRT - 2025.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Static parameters
SCRIPT_DIR="$(dirname "$0")"
INSTALL_YARA_SCRIPT="$SCRIPT_DIR/installyara.sh"
YARA_SCRIPT="$SCRIPT_DIR/yara.sh"
UPDATE_RULES_SCRIPT="$SCRIPT_DIR/update_rules.sh"
WAZUH_AR_DIR="/var/ossec/active-response/bin"
SCRIPTS_DEST_DIR="/usr/local/scripts"
LOG_FILE="/var/log/yara_wazuh_setup.log"
CRON_SCHEDULE="0 2 * * *"
CRON_JOB="$CRON_SCHEDULE $SCRIPTS_DEST_DIR/update_rules.sh >> /var/log/yara_rules_update.log 2>&1"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if Wazuh agent is installed and running
check_wazuh_agent() {
    if ! command_exists /var/ossec/bin/wazuh-control; then
        log_message "ERROR: Wazuh agent is not installed."
        echo "ERROR: Wazuh agent is not installed. Please install it first."
        exit 1
    fi
    if ! /var/ossec/bin/wazuh-control status >/dev/null 2>&1; then
        log_message "ERROR: Wazuh agent is not running."
        echo "ERROR: Wazuh agent is not running. Please start it first."
        exit 1
    fi
    log_message "INFO: Wazuh agent is installed and running."
}

# Function to validate and execute a script
execute_script() {
    local script_path="$1"
    if [ ! -f "$script_path" ]; then
        log_message "ERROR: Script $script_path not found in $SCRIPT_DIR."
        echo "ERROR: Script $script_path not found."
        exit 1
    fi
    if ! chmod +x "$script_path"; then
        log_message "ERROR: Failed to make $script_path executable."
        echo "ERROR: Failed to set executable permissions for $script_path."
        exit 1
    fi
    if ! bash "$script_path"; then
        log_message "ERROR: Execution of $script_path failed."
        echo "ERROR: Failed to execute $script_path."
        exit 1
    fi
    log_message "INFO: Successfully executed $script_path."
}

# Function to setup yara.sh for Wazuh active response
setup_yara_active_response() {
    if [ ! -f "$YARA_SCRIPT" ]; then
        log_message "ERROR: yara.sh not found in $SCRIPT_DIR."
        echo "ERROR: yara.sh not found."
        exit 1
    fi
    if ! mkdir -p "$WAZUH_AR_DIR"; then
        log_message "ERROR: Failed to create directory $WAZUH_AR_DIR."
        echo "ERROR: Failed to create Wazuh active response directory."
        exit 1
    fi
    if ! cp "$YARA_SCRIPT" "$WAZUH_AR_DIR/"; then
        log_message "ERROR: Failed to copy yara.sh to $WAZUH_AR_DIR."
        echo "ERROR: Failed to copy yara.sh to Wazuh active response directory."
        exit 1
    fi
    if ! chmod +x "$WAZUH_AR_DIR/yara.sh"; then
        log_message "ERROR: Failed to set executable permissions for $WAZUH_AR_DIR/yara.sh."
        echo "ERROR: Failed to set permissions for yara.sh."
        exit 1
    fi
    if ! chown root:root "$WAZUH_AR_DIR/yara.sh"; then
        log_message "WARNING: Failed to set ownership for $WAZUH_AR_DIR/yara.sh."
        echo "WARNING: Failed to set ownership for yara.sh."
    fi
    log_message "INFO: Successfully set up yara.sh in $WAZUH_AR_DIR."
}

# Function to setup update_rules.sh and schedule cronjob
setup_rules_update_cron() {
    if [ ! -f "$UPDATE_RULES_SCRIPT" ]; then
        log_message "ERROR: update_rules.sh not found in $SCRIPT_DIR."
        echo "ERROR: update_rules.sh not found."
        exit 1
    fi
    if ! mkdir -p "$SCRIPTS_DEST_DIR"; then
        log_message "ERROR: Failed to create directory $SCRIPTS_DEST_DIR."
        echo "ERROR: Failed to create scripts destination directory."
        exit 1
    fi
    if ! cp "$UPDATE_RULES_SCRIPT" "$SCRIPTS_DEST_DIR/"; then
        log_message "ERROR: Failed to copy update_rules.sh to $SCRIPTS_DEST_DIR."
        echo "ERROR: Failed to copy update_rules.sh to scripts directory."
        exit 1
    fi
    if ! chmod +x "$SCRIPTS_DEST_DIR/update_rules.sh"; then
        log_message "ERROR: Failed to set executable permissions for $SCRIPTS_DEST_DIR/update_rules.sh."
        echo "ERROR: Failed to set permissions for update_rules.sh."
        exit 1
    fi
    if ! chown root:root "$SCRIPTS_DEST_DIR/update_rules.sh"; then
        log_message "WARNING: Failed to set ownership for $SCRIPTS_DEST_DIR/update_rules.sh."
        echo "WARNING: Failed to set ownership for update_rules.sh."
    fi
    log_message "INFO: Successfully copied update_rules.sh to $SCRIPTS_DEST_DIR."

    # Check if cronjob already exists
    if crontab -l 2>/dev/null | grep -q "$SCRIPTS_DEST_DIR/update_rules.sh"; then
        log_message "INFO: Cronjob for update_rules.sh already exists."
        echo "INFO: Cronjob already exists. Skipping cronjob setup."
        return
    fi

    # Add cronjob
    if ! (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -; then
        log_message "ERROR: Failed to add cronjob for update_rules.sh."
        echo "ERROR: Failed to schedule cronjob for rules update."
        exit 1
    fi
    log_message "INFO: Successfully scheduled cronjob to run at 2 AM daily."
    echo "INFO: Cronjob scheduled to update Yara rules daily at 2 AM."
}

# Main execution
log_message "INFO: Starting Yara and Wazuh active response setup with cronjob automation..."

# Check for Wazuh agent
echo "Checking Wazuh agent status..."
check_wazuh_agent

# Execute installyara.sh
echo "Executing installyara.sh..."
execute_script "$INSTALL_YARA_SCRIPT"

# Setup yara.sh for Wazuh active response
echo "Setting up yara.sh for Wazuh active response..."
setup_yara_active_response

# Setup update_rules.sh and cronjob
echo "Setting up Yara rules update script and scheduling cronjob..."
setup_rules_update_cron

log_message "INFO: Yara and Wazuh active response setup with cronjob completed successfully."
echo "Installation and configuration of Yara for Wazuh with automated rules update completed successfully."

exit 0