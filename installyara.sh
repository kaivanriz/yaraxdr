#!/bin/bash
# Yara rules - Compiled file creation
# Copyright (C) SOCFortress, LLP.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#
#------------------------- Aadjust IFS to read files -------------------------#
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Folder where Yara rules (files) will be placed -------------------------#
mkdir /tmp/quarantined
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_yara() {
  wget -N https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.1.tar.gz
  tar -zxf v4.5.1.tar.gz
  cd yara-4.5.1
  ./bootstrap.sh
  ./configure
  make
  sudo make install
  make check
  mv yara /usr/bin/
  mv yarac /usr/bin/
}
install_yara2() {
    yum install -y yara 
}


if command_exists yara; then
  echo "Yara is already installed."

else
  install_yara2
  echo "Yara installation script completed."

fi

git_repo_folder="/usr/local/signature-base"
if [ ! -d "$git_repo_folder" ]; then
    # If the directory doesn't exist, create it
    mkdir -p "$git_repo_folder"
    echo "Directory $git_repo_folder created."
else
    echo "Directory $git_repo_folder already exists."
fi

if [ -d "$git_repo_folder/.git" ]; then
        echo "Directory $git_repo_folder is a Git repository."
else
        echo "Directory $git_repo_folder is not a Git repository. Initializing..."
        cd "$git_repo_folder"
        git init
        echo "Directory $git_repo_folder initialized as a Git repository."
fi


yara_file_extenstions=( ".yar" )
yara_rules_list="/usr/local/signature-base/yara_rules_list.yar"

#------------------------- Main workflow --------------------------#

# Update Github Repo
cd $git_repo_folder


git pull https://github.com/noplanalderson/yara_rules.git

# Remove .yar files not compatible with standard Yara package
rm -f $git_repo_folder/yara/gen_fake_amsi_dll.yar
rm -f $git_repo_folder/yara/gen_vcruntime140_dll_sideloading.yar
rm -f $git_repo_folder/yara/expl_connectwise_screenconnect_vuln_feb24.yar
rm -f $git_repo_folder/yara/yara-rules_vuln_drivers_strict_renamed.yar
rm -f $git_repo_folder/yara/gen_mal_3cx_compromise_mar23.yar
rm -f $git_repo_folder/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar
rm -f $git_repo_folder/yara/yara_mixed_ext_vars.yar
rm -f $git_repo_folder/yara/thor_inverse_matches.yar
rm -f $git_repo_folder/yara/generic_anomalies.yar
rm -f $git_repo_folder/yara/gen_webshells_ext_vars.yar
rm -f $git_repo_folder/yara/general_cloaking.yar
rm -f $git_repo_folder/yara/configured_vulns_ext_vars.yar
rm -f $git_repo_folder/yara/php_webshell_rules.yara

wget -P $git_repo_folder/yara/ https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/php_webshell_rules.yara


# Create File with rules to be compiled
if [ ! -f $yara_rules_list ]
then
    /usr/bin/touch $yara_rules_list
else rm $yara_rules_list
fi
for e in "${yara_file_extenstions[@]}"
do
  for f1 in $( find $git_repo_folder/yara -type f | grep -F $e ); do
    echo "include \"""$f1"\""" >> $yara_rules_list
  done
done
# Compile Yara Rules
yarac $yara_rules_list /usr/local/signature-base/yara_base_ruleset_compiled.yar
IFS=$SAVEIFS
exit 1;
