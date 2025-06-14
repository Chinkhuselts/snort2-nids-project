#!/bin/bash
sudo apt update && sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev openssl libssl-dev
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
tar -xvzf daq-2.0.7.tar.gz && cd daq-2.0.7
./configure && make && sudo make install
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
tar -xvzf snort-2.9.20.tar.gz && cd snort-2.9.20
./configure --enable-sourcefire && make && sudo make install
sudo mkdir -p /etc/snort /etc/snort/rules /var/log/snort
sudo cp etc/snort.conf /etc/snort/
sudo cp configs/local.rules /etc/snort/rules/
sudo ldconfig
