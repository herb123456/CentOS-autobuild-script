#!/bin/bash

./variable.sh &&
./setTimezone.sh &&
./upgradeYum.sh &&
./sshd.sh && 
./fail2ban.sh &&
./nginx_modsecurity_letsencrypt.sh &&
./php7.sh &&
./mariadb.sh &&
./postfix.sh &&
./final_nginx_config.sh &&
./ohmyzsh.sh