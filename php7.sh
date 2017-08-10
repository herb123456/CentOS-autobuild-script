#!/bin/bash

source variable.sh


# install php
yum install -y php71 php71-php-cli.x86_64 php71-php-common.x86_64  php71-php-fpm.x86_64  php71-php-gd.x86_64 php71-php-intl.x86_64 php71-php-json.x86_64 php71-php-mbstring.x86_64 php71-php-mcrypt.x86_64 php71-php-mysqlnd.x86_64 php71-php-opcache.x86_64 php71-php-pdo.x86_64 php71-php-pear.noarch php71-php-pecl-apcu.x86_64 php71-php-pecl-igbinary.x86_64 php71-php-pecl-memcache.x86_64 php71-php-pecl-memcached.x86_64 php71-php-pecl-mongodb.x86_64 php71-php-pecl-redis.x86_64 php71-php-pecl-yaml.x86_64 php71-php-soap.x86_64 php71-php-tidy.x86_64 php71-php-xml.x86_64 php71-php-xmlrpc.x86_64 php71-php-pecl-zip.x86_64

source /opt/remi/php71/enable

sed -ie "s/opcache.huge_code_pages=1/opcache.huge_code_pages=0/g" /etc/opt/remi/php71/php.d/10-opcache.ini

# change log location
sed -ie '/^error_log =.*log$/aerror_log = /var/log/php-fpm/php71-error.log' /etc/opt/remi/php71/php-fpm.conf
sed -i -n '/^error_log.*remi.*log$/!p' /etc/opt/remi/php71/php-fpm.conf
sed -ie 's/\/var\/opt\/remi\/php71\/log\//\/var\/log\//g' /etc/opt/remi/php71/php-fpm.d/www.conf

# change run user and group
sed -i "s/user = apache/user = nginx/g" /etc/opt/remi/php71/php-fpm.d/www.conf
sed -i "s/group = apache/group = nginx/g" /etc/opt/remi/php71/php-fpm.d/www.conf

# change listen port to socket file
sed -i "s/listen = 127.0.0.1:9000/listen = \/var\/run\/php71-fpm.sock/g" /etc/opt/remi/php71/php-fpm.d/www.conf
sed -i "s/;listen.owner = nobody/listen.owner = nginx/g" /etc/opt/remi/php71/php-fpm.d/www.conf
sed -i "s/;listen.group = nobody/listen.group = nginx/g" /etc/opt/remi/php71/php-fpm.d/www.conf
sed -i "s/;listen.mode = 0660/listen.mode = 0660/g" /etc/opt/remi/php71/php-fpm.d/www.conf

mkdir /var/log/php-fpm

systemctl start php71-php-fpm.service