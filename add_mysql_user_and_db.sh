#!/bin/sh
if [ $# -lt 3 ]; then
	echo "Usage: $0 root_password dbname username password"
	exit
fi

user="root"
pass=$1

mysql -u "$user" -p"$pass" <<EOF
    CREATE DATABASE $2;
    CREATE USER '$3'@'localhost' IDENTIFIED BY '$4';
    GRANT ALL PRIVILEGES ON $2 . * TO '$3'@'localhost';
EOF