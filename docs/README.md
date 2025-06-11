# Snort 2 NIDS Project README

Welcome to my **Snort 2 Network Intrusion Detection System (NIDS)** project, a cybersecurity portfolio piece demonstrating my skills in network security, Linux administration, and intrusion detection. This project uses **Snort 2.9.20** to detect unauthorized network activities, such as ICMP pings and TCP SYN scans, on a test network.

## Project Overview
- **Objective**: Deploy a NIDS to monitor network traffic and detect malicious activities in real-time.
- **Tools**: Snort 2.9.20, Ubuntu 22.04 LTS, Nmap, Wireshark, VirtualBox.
- **Features**:
  - Custom rules to detect ICMP pings and port scans.
  - Console-based alert logging.
  - Visualization of alert counts using Chart.js.
- **Results**: Successfully detected 15 ICMP pings and 6 TCP SYN scans in a controlled test environment.

## Repository Structure
- `configs/`: Snort configuration (`snort.conf`) and custom rules (`local.rules`).
- `logs/`: Sample alert output (`sample_alerts.txt`).
- `docs/`: Detailed documentation (`REPORT.md`, `SETUP.md`).
- `scripts/`: Automation scripts for setup.
- `media/`: Demo video and alert chart screenshot.

## Getting Started
1. Clone the repository:
   ```bash
   git clone https://github.com/Chinkhuselts/snort2-nids-project.git

2. Follow SETUP.md for installation and configuration instructions.
3. To simulate attack, use Nmap and Ping tools
## Detailed Report

Read the full project report in REPORT.md for methodology, results, and lessons learned.
