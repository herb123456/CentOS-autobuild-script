#!/bin/bash

source variable.sh

# Edit sshd config

sed -i -E 's/#?PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i "s/#Port 22/Port $SSHD_LISTEN_PORT/g" /etc/ssh/sshd_config

# add user
useradd $SSH_USER_NAME
passwd $SSH_USER_NAME

systemctl restart sshd