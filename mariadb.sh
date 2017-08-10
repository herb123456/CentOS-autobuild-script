#!/bin/bash

source variable.sh

# install mariadb
/bin/cat <<EOM >/etc/yum.repos.d/Mariadb.repo
# MariaDB 10.1 CentOS repository list - created 2017-01-10 15:14 UTC
# http://downloads.mariadb.org/mariadb/repositories/
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.1/centos7-amd64
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1
EOM

yum -y install MariaDB-server MariaDB-client

# mysql secure setup
systemctl start mysql
mysql_secure_installation