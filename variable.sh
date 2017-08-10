#!/bin/bash

# working directory
WORKING_DIR=`pwd`

# another user for ssh login
SSH_USER_NAME="herb"

# sshd listen port
SSHD_LISTEN_PORT="2200"

# Timezone
TIMEZONE="Asia/Taipei"

# modsecurity version
MOD_VERSION="2.9.1"

# nginx version
NGINX_VERSION="1.10.3"

# iptables binary path
IPTABLE="/sbin/iptables"

# external interface
EXTINF="eth0"

# open input ports
OPEN_INPUT_PORTS="25 80 443 2200"

# open output ports
OPEN_OUTPUT_PORTS="25 80 443 53 123"

PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin;

export PATH WORKING_DIR SSH_USER_NAME SSHD_LISTEN_PORT TIMEZONE MOD_VERSION NGINX_VERSION IPTABLE EXTINF OPEN_INPUT_PORTS OPEN_OUTPUT_PORTS
