#!/bin/bash

source variable.sh

# install fail2ban
yum -y install fail2ban

# enable sshd jail
/bin/cat <<EOM >/etc/fail2ban/jail.local
[DEFAULT]
# Ban hosts for one hour:
bantime = 3600

# Override /etc/fail2ban/jail.d/00-firewalld.conf:
banaction = iptables-multiport


[sshd]
port = $SSHD_LISTEN_PORT
bantime = 86400
enabled = true
EOM

systemctl start fail2ban