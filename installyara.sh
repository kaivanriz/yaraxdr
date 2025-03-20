#!/bin/bash
# Yara rules - Compiled file creation
# Copyright (C) SOCFortress, LLP.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Adjust IFS to read files
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")

# Static active response parameters
LOCAL=$(dirname "$0")

# Detect OS type
OS_TYPE=$(uname -s)
OS_FAMILY="unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_FAMILY=$ID
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    OS_FAMILY="macos"
elif [[ "$OS_TYPE" == "Linux" ]]; then
    OS_FAMILY="linux"
fi

# Install required packages for compiling from source
install_build_dependencies() {
    case "$OS_FAMILY" in
        "ubuntu"|"debian")
            sudo apt update && sudo apt install -y build-essential automake libtool pkg-config wget git ;; 
        "centos"|"rhel"|"fedora"|"almalinux")
            sudo yum groupinstall -y "Development Tools" && sudo yum install -y automake libtool pkg-config wget git ;;
        "macos")
            brew install automake libtool pkg-config wget ;;
    esac
}

# Create quarantine folder
mkdir -p /tmp/quarantined

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_yara_from_source() {
  install_build_dependencies
  wget -N https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.1.tar.gz
  tar -zxf v4.5.1.tar.gz
  cd yara-4.5.1 || exit 1
  autoreconf -fi
  ./configure
  make
  sudo make install
  make check
  sudo mv /usr/local/bin/yara /usr/bin/
  sudo mv /usr/local/bin/yarac /usr/bin/
}

install_yara_linux() {
    if command_exists dnf; then
        sudo dnf install -y yara
    else
        sudo yum install -y yara
    fi
}

install_yara_macos() {
    brew install yara
}

# Install Yara based on OS
if command_exists yara; then
    echo "Yara is already installed."
else
    case "$OS_FAMILY" in
        "ubuntu"|"debian") sudo apt update && sudo apt install -y yara ;; 
        "centos"|"rhel"|"fedora"|"almalinux") install_yara_linux ;;
        "macos") install_yara_macos ;;
        *) install_yara_from_source ;;
    esac
    echo "Yara installation completed."
fi

# Git repository setup
git_repo_folder="/usr/local/signature-base"
mkdir -p "$git_repo_folder"

if [ ! -d "$git_repo_folder/.git" ]; then
    cd "$git_repo_folder" || exit 1
    git init
    echo "Initialized Git repository in $git_repo_folder"
fi

# Update GitHub Repo
cd "$git_repo_folder" || exit 1
git pull https://github.com/noplanalderson/yara_rules.git

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
    rm -f "$git_repo_folder/yara/$rule"
done

# Download replacement rule
wget -P "$git_repo_folder/yara/" https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/php_webshell_rules.yara

# Create and compile Yara rules
yara_rules_list="$git_repo_folder/yara_rules_list.yar"
rm -f "$yara_rules_list"
touch "$yara_rules_list"

for f in "$git_repo_folder/yara"/*.yar; do
    echo "include \"$f\"" >> "$yara_rules_list"
done

yarac "$yara_rules_list" "$git_repo_folder/yara_base_ruleset_compiled.yar"
IFS=$SAVEIFS
exit 0
