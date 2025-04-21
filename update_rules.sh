#!/bin/bash
# Yara Rules Update Script for Cronjob
# Copyright (C) TangerangKota-CSIRT - 2025.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Adjust IFS to read files
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")

# Static parameters
GIT_REPO_FOLDER="/usr/local/signature-base"
YARA_RULES_LIST="$GIT_REPO_FOLDER/yara_rules_list.yar"
COMPILED_RULES="$GIT_REPO_FOLDER/yara_base_ruleset_compiled.yar"
LOG_FILE="/var/log/yara_rules_update.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Check if required commands exist
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Ensure required tools are installed
if ! command_exists git || ! command_exists yarac || ! command_exists wget; then
    log_message "ERROR: Required tools (git, yarac, or wget) are missing. Please install them."
    exit 1
fi

# Check if Git repository exists
if [ ! -d "$GIT_REPO_FOLDER/.git" ]; then
    log_message "ERROR: Git repository not found at $GIT_REPO_FOLDER. Please run the initial setup script."
    exit 1
fi

# Update GitHub repository
log_message "INFO: Updating Yara rules from GitHub repository..."
cd "$GIT_REPO_FOLDER" || {
    log_message "ERROR: Failed to change to $GIT_REPO_FOLDER directory."
    exit 1
}
git pull https://github.com/noplanalderson/yara_rules.git >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
    log_message "ERROR: Failed to pull updates from GitHub repository."
    exit 1
fi

# Remove incompatible Yara files
declare -a yara_blacklist=(
    "gen_fake_amsi_dll.yar"
    "gen_vcruntime140_dll_sideloading.yar"
    "expl_connectwise_screenconnect_vuln_feb24.yar"
    "yara-rules_vuln_drivers_strict_renamed.yar"
    "gen_mal_3cx_compromise_mar23.yar"
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar"
    "yara_mixed_ext_vars.yar"
    "thor_inverse_matches.yar"
    "generic_anomalies.yar"
    "gen_webshells_ext_vars.yar"
    "general_cloaking.yar"
    "configured_vulns_ext_vars.yar"
    "php_webshell_rules.yara"
)

for rule in "${yara_blacklist[@]}"; do
    rm -f "$GIT_REPO_FOLDER/yara/$rule"
done
log_message "INFO: Removed incompatible Yara rule files."

# Download replacement rule
wget -q -O "$GIT_REPO_FOLDER/yara/php_webshell_rules.yara" https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/php_webshell_rules.yara >> "$LOG_FILE" 2>&1
if [ $? -eq 0 ]; then
    log_message "INFO: Successfully downloaded php_webshell_rules.yara."
else
    log_message "ERROR: Failed to download php_webshell_rules.yara."
    exit 1
fi

# Create and compile Yara rules
rm -f "$YARA_RULES_LIST"
touch "$YARA_RULES_LIST"

for f in "$GIT_REPO_FOLDER/yara"/*.yar; do
    echo "include \"$f\"" >> "$YARA_RULES_LIST"
done

yarac "$YARA_RULES_LIST" "$COMPILED_RULES" >> "$LOG_FILE" 2>&1
if [ $? -eq 0 ]; then
    log_message "INFO: Successfully compiled Yara rules to $COMPILED_RULES."
else
    log_message "ERROR: Failed to compile Yara rules."
    exit 1
fi

# Restore IFS
IFS=$SAVEIFS
log_message "INFO: Yara rules update completed successfully."
exit 0