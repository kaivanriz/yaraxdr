#!/bin/bash

# Define the URL variables
INSTALL_YARA_SCRIPT_URL="https://raw.githubusercontent.com/kaivanriz/yaraxdr/main/installyara.sh"
YARA_SCRIPT_URL="https://raw.githubusercontent.com/kaivanriz/yaraxdr/main/yara.sh"

# Function to check if Wazuh agent is installed
check_wazuh_agent_installed() {
  if ! command -v /var/ossec/wazuh-control status > /dev/null; then
    echo "Wazuh agent is not installed. Please install the Wazuh agent first."
    exit 1
  fi
}

# Function to check if Wazuh agent is running


# Check if Wazuh agent is installed
echo "Checking if Wazuh agent is installed..."
check_wazuh_agent_installed



# Download installyara.sh script
echo "Downloading installyara.sh script..."
curl -o /tmp/installyara.sh $INSTALL_YARA_SCRIPT_URL

# Make the installyara.sh script executable
chmod +x /tmp/installyara.sh

# Execute installyara.sh script
echo "Executing installyara.sh script..."
/bin/bash /tmp/installyara.sh

# Download yara.sh script
echo "Downloading yara.sh script and move to wazuh active-response..."
curl -o /var/ossec/active-response/bin/yara.sh $YARA_SCRIPT_URL

# Set permissions for yara.sh
echo "Setting permissions for yara.sh..."
chmod u+x /var/ossec/active-response/bin/yara.sh

echo "Installation and configuration of YARA completed successfully."
