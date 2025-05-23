
# Project Title
Yara XDR for Wazuh


## How to use
1. Install Git
``` bash
// For Debian Family
# apt install git
// For RHEL Family
# yum install git
```

2. Download and Extract
``` bash
# cd /home
# git clone https://github.com/kaivanriz/yaraxdr.git
```

3. Install Yara
``` bash
# cd /home/yaraxdr
# bash setup.sh
```

3. Configure Wazuh Agent
``` bash
# nano /var/ossec/etc/ossec.conf
```
Add this script below in the ``<syscheck>`` directives
``` xml
<directories check_all="no" check_sum="yes" check_size="yes" check_mtime="yes" realtime="yes">/path/to/assets/or/upload/directory/</directories>
<!-- Optional -->
<directories check_all="no" check_sum="yes" check_size="yes" check_mtime="yes" realtime="yes">/path/to/assets/or/upload/directory2/</directories>
<directories check_all="no" check_sum="yes" check_size="yes" check_mtime="yes" realtime="yes">/path/to/assets/or/upload/directory3/</directories>
```
``` bash
# systemctl restart wazuh-agent
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
This project is open source and available under the [MIT License](LICENSE).

  
