# Snort 2 NIDS Project Report

## Introduction
As a cybersecurity student, I developed a **Network Intrusion Detection System (NIDS)** using **Snort 2.9.20** to monitor network traffic and detect unauthorized activities, such as ICMP pings and port scans. This project showcases my skills in network security, Linux administration, and intrusion detection, making it a key piece for my portfolio.

## Problem Statement
Unauthorized network activities, like ping sweeps and port scans, are common precursors to cyberattacks. A NIDS is essential for detecting these threats in real-time to enable rapid response and mitigation.

## Solution Overview
I deployed **Snort 2.9.20** on **Ubuntu 22.04 LTS** in a virtualized test network, configured custom rules to detect ICMP pings and TCP SYN scans, and logged alerts for analysis. The project involved setting up Snort, validating configurations, simulating attacks, and documenting results.

## Tools and Technologies
- **Snort 2.9.20**: Open-source NIDS for real-time traffic analysis.
- **Ubuntu 22.04 LTS**: Host OS on a VirtualBox VM.
- **Nmap**: Simulated port scans.
- **Wireshark**: Validated captured traffic.
- **VirtualBox**: Created a test network with Snort and attacker VMs.
- **GitHub**: Hosted at [github.com/Chinkhuselts/snort2-nids-project](https://github.com/Chinkhuselts/snort2-nids-project).

## Implementation

### 1. Environment Setup
- Configured two VirtualBox VMs on a NAT network:
  - **Snort VM**: Ubuntu 22.04, 4 GB RAM, 2 CPUs, eth0 in promiscuous mode:
    sudo ip link set eth0 promisc on
Attacker VM: Ubuntu 22.04 for attack simulation.
Installed Snort 2.9.20 and DAQ 2.0.7 from snort.org/downloads:
    sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev openssl libssl-dev
    wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
    tar -xvzf daq-2.0.7.tar.gz && cd daq-2.0.7
    ./configure && make && sudo make install
    wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
    tar -xvzf snort-2.9.20.tar.gz && cd snort-2.9.20
    ./configure --enable-sourcefire && make && sudo make install

### 2. Snort Configuration

    Created directories: /etc/snort, /etc/snort/rules, /var/log/snort.
    Updated network variables:
ipvar HOME_NET 192.168.1.0/24
ipvar EXTERNAL_NET !$HOME_NET
Enabled logging:
conf
output unified2: filename snort.log, limit 128
Included rules:
    include $RULE_PATH/local.rules

Created local.rules:
    alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
    alert tcp any any -> $HOME_NET any (msg:"TCP SYN Scan Detected"; flags:S; sid:1000002; rev:1;)

### 3. Configuration Validation

    Tested configuration to ensure no errors:
    sudo snort -T -c /etc/snort/snort.conf
    Verified snort.conf and local.rules syntax to avoid issues like missing files or invalid rules.

### 4. Attack Simulation

    Ran Snort in NIDS mode:
    sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
    Simulated attacks from the attacker VM:
        ICMP Ping: ping 192.168.1.100.
        Port Scan: nmap 192.168.1.100.
    Used Wireshark to capture and verify traffic.

Results

    Alerts Generated:
        15 ICMP ping alerts.
        6 TCP SYN scan alerts.
    Sample Alert (Console Output):
06/11-14:30:22.123456 [**] [1:1000001:1] ICMP Ping Detected [**] [Priority: 0] {ICMP} 192.168.1.101 -> 192.168.1.100
Validation: Wireshark confirmed matching ICMP and TCP SYN packets.
Mitigation Recommendations:
    Block malicious IPs using iptables.
    Integrate Other Snort rules for bigger purpose.
