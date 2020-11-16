#!/bin/bash
echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sudo service network-manager restart
# /etc/init.d/network restart
