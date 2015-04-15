#!/bin/bash

# working directory
WORKING_DIR=`pwd`

# another user for ssh login
SSH_USER_NAME="herb"

# sshd listen port
SSHD_LISTEN_PORT="993"

# nginx version
NGINX_VERSION="1.7.11"

# openssl version
OPENSSL_VERSION="1.0.2a"

# page speed module for nginx
NGINX_PAGESPEED_VERSION="1.9.32.3"

# mod_security version
MOD_SECURITY_VERSION="2.9.0"

# php version
PHP_VERSION="5.6.7"

LIB_MCRYPT_VERSION="2.5.8"

# document root
# DOCUMENT_ROOT="/var/www/html"

# processor number
# PROCESSOR_NUM=`grep ^processor /proc/cpuinfo | wc -l`

# iptables binary path
IPTABLE="/sbin/iptables"

# external interface
EXTINF="eth0"

# open input ports
OPEN_INPUT_PORTS="80 993"

# open output ports
OPEN_OUTPUT_PORTS="25 80 443 53 123"

# alert email
ALERT_EMAIL=herb123456@gmail.com

# mail domain
MAIL_DOMAIN=iphpo.com

# mail hostname
MAIL_HOSTNAME=mail.iphpo.com

PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin;

export PATH WORKING_DIR SSH_USER_NAME SSHD_LISTEN_PORT NGINX_VERSION OPENSSL_VERSION NGINX_PAGESPEED_VERSION MOD_SECURITY_VERSION PHP_VERSION LIB_MCRYPT_VERSION DOCUMENT_ROOT IPTABLE EXTINF OPEN_INPUT_PORTS OPEN_OUTPUT_PORTS ALERT_EMAIL MAIL_DOMAIN MAIL_HOSTNAME

cd $WORKING_DIR

###################
#                 #  
#  configure ssh  #
#                 #
###################

useradd $SSH_USER_NAME
passwd $SSH_USER_NAME

# disable root login
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
# change sshd listen port
sed -i "s/#Port 22/Port $SSHD_LISTEN_PORT/g" /etc/ssh/sshd_config

# restart sshd service
/etc/init.d/sshd restart

###########################
#                         #  
#  install compile tools  #
#                         #
###########################

yum -y update
yum -y install git epel-release gcc gcc-c++ autoconf libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel libxml2 libxml2-devel zlib zlib-devel glibc glibc-devel glib2 glib2-devel bzip2 bzip2-devel ncurses ncurses-devel curl curl-devel httpd-devel pcre-devel sqlite sqlite-devel gdbm gdbm-devel db4-devel libdbi-devel libdbi tokyocabinet tokyocabinet-devel enchant-devel libvpx-devel libXpm-devel t1lib-devel t1lib gd gd-devel gmp gmp-devel libc-client-devel krb5-devel krb5-libs icu libicu libicu-devel unixODBC unixODBC-devel postgresql-devel aspell-devel libedit libedit-devel libtidy libtidy-devel recode recode-devel net-snmp-devel net-snmp-libs net-snmp-utils libxslt libxslt-devel kernel-devel systemtap-sdt-devel libtool-ltdl-devel sendmail-devel


###################
#                 #  
#  compile nginx  #
#                 #
###################

# make working directory
mkdir nginx
cd nginx

# download nginx source
wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
# download openssl source
wget https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz
# download pagespeed nginx module source code
wget https://github.com/pagespeed/ngx_pagespeed/archive/release-$NGINX_PAGESPEED_VERSION-beta.zip
# download naxsi source code
wget https://github.com/nbs-system/naxsi/archive/master.zip -O naxsi.zip
# download mod_security source code
wget https://www.modsecurity.org/tarball/2.9.0/modsecurity-$MOD_SECURITY_VERSION.tar.gz

# untar all tar ball
tar zxvf nginx-$NGINX_VERSION.tar.gz
tar zxvf openssl-$OPENSSL_VERSION.tar.gz
unzip release-$NGINX_PAGESPEED_VERSION-beta.zip
unzip naxsi.zip
tar zxvf modsecurity-$MOD_SECURITY_VERSION.tar.gz

# compile pagespeed
cd ngx_pagespeed-release-$NGINX_PAGESPEED_VERSION-beta
wget https://dl.google.com/dl/page-speed/psol/$NGINX_PAGESPEED_VERSION.tar.gz
tar zxvf $NGINX_PAGESPEED_VERSION.tar.gz
cd ..

# compile openssl
cd openssl-$OPENSSL_VERSION
./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib shared zlib-dynamic
make
make MANDIR=/usr/share/man MANSUFFIX=ssl install && install -dv -m755 /usr/share/doc/openssl-$OPENSSL_VERSION  && cp -vfr doc/* /usr/share/doc/openssl-$OPENSSL_VERSION

# link to another lib directory
ln -s /usr/lib/libssl.so.1.0.0 /lib64/libssl.so.1.0.0
ln -s /usr/lib/libssl.so.1.0.0 /usr/lib64/libssl.so.1.0.0
ln -s /usr/lib/libssl.so /lib64/libssl.so
ln -s /usr/lib/libcrypto.so.1.0.0 /lib64/libcrypto.so.1.0.0
ln -s /usr/lib/libcrypto.so.1.0.0 /usr/lib64/libcrypto.so.1.0.0
ln -s /usr/lib/libcrypto.so /lib64/libcrypto.so

cd ..

# compile mod_security
cd modsecurity-$MOD_SECURITY_VERSION
./configure --enable-standalone-module --disable-mlogc
make
cd ..

# compile nginx
cd nginx-$NGINX_VERSION
sed -i "s/Server: nginx/Server: Hello/g" src/http/ngx_http_header_filter_module.c
./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-http_ssl_module --with-http_realip_module --with-http_addition_module --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_stub_status_module --with-http_auth_request_module --with-mail --with-mail_ssl_module --with-file-aio --with-ipv6 --with-http_spdy_module --with-cc-opt='-O2 -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' --add-module=../naxsi-master/naxsi_src/ --add-module=../modsecurity-$MOD_SECURITY_VERSION/nginx/modsecurity/ --add-module=../ngx_pagespeed-release-$NGINX_PAGESPEED_VERSION-beta/ --with-cc-opt="-I /usr/include/openssl" --with-ld-opt="-L /usr/lib"
make
make install
cp $WORKING_DIR/init/nginx /etc/init.d/nginx
chmod +x /etc/init.d/nginx
cd ..

# compile nginx finished
cd ..

##################
#                #  
#  compile php5  #
#                #
##################

mkdir php5
cd php5

# download php source code
wget http://tw1.php.net/get/php-$PHP_VERSION.tar.gz/from/this/mirror -O php-$PHP_VERSION.tar.gz
# download mcrypt source code
wget http://softlayer.dl.sourceforge.net/sourceforge/mcrypt/libmcrypt-$LIB_MCRYPT_VERSION.tar.gz
# download libzip source code
wget -4 http://www.nih.at/libzip/libzip-0.11.2.tar.gz

# untar all tar ball
tar zxvf php-$PHP_VERSION.tar.gz
tar zxvf libmcrypt-$LIB_MCRYPT_VERSION.tar.gz
tar zxvf libzip-0.11.2.tar.gz

# compile mcrypt
cd libmcrypt-$LIB_MCRYPT_VERSION
./configure --prefix=/usr/local
make
make install
cd ..

# compile libzip
cd libzip-0.11.2
./configure --prefix=/usr/local
make
make install
cp /usr/local/lib/libzip/include/zipconf.h /usr/include/
ln -s /usr/local/lib/libzip.so.2.1.0 /lib64/libzip.so.2
ln -s /usr/local/lib/libzip.so.2.1.0 /lib64/libzip.so
cd ..

# add ldconfig
cat <<EOT >> /etc/ld.so.conf.d/local.conf
/usr/local/lib
/usr/local/lib64
EOT
ldconfig -v

# compile php
cd php-$PHP_VERSION

# add apcu and xdebug module
cd ext
git clone https://github.com/krakjoe/apcu.git
git clone https://github.com/xdebug/xdebug.git
cd ..
mv configure configure_back
# force rebuild conig
sed -i "/debug=no/adevok=1" buildconf
./buildconf -—force

# make
./configure --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib64 --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info --with-libdir=lib64 --with-config-file-path=/etc --with-config-file-scan-dir=/etc/php.d --disable-debug --with-pic --disable-rpath --with-pear --with-freetype-dir=/usr --with-png-dir=/usr --with-xpm-dir=/usr --with-vpx-dir=/usr --enable-gd-native-ttf --with-t1lib=/usr --with-jpeg-dir=/usr --with-openssl --with-system-ciphers --with-zlib --with-layout=GNU --with-kerberos --with-libxml-dir=/usr --with-mhash --libdir=/usr/lib64/php --enable-pcntl --enable-opcache --enable-phpdbg --with-imap --with-imap-ssl --enable-mbstring --enable-mbregex --with-gd --with-gmp --enable-calendar --enable-bcmath --with-bz2 --enable-ctype --with-tcadb=/usr --enable-exif --enable-ftp --with-gettext --with-iconv=shared --enable-sockets --enable-tokenizer --with-xmlrpc --with-ldap=shared --with-ldap-sasl --enable-mysqlnd --with-mysql=shared,mysqlnd --with-mysqli=shared,mysqlnd --with-mysql-sock=/var/lib/mysql/mysql.sock --enable-dom=shared --with-pgsql --enable-simplexml --enable-xml --enable-wddx=shared --with-snmp=shared,/usr --enable-soap=shared --with-xsl=shared,/usr --enable-xmlreader=shared --enable-xmlwriter=shared --with-curl --enable-pdo --with-pdo-odbc=shared,unixODBC,/usr --with-pdo-mysql=shared,mysqlnd --with-pdo-pgsql=shared,/usr --with-pdo-sqlite=shared,/usr --with-sqlite3=shared,/usr --with-readline --with-libedit --with-pspell=shared --enable-phar --with-mcrypt --with-tidy=shared,/usr --enable-sysvmsg=shared --enable-sysvshm=shared --enable-sysvsem=shared --enable-shmop=shared --enable-posix=shared --with-unixODBC=shared,/usr --enable-fileinfo --enable-intl --with-icu-dir=/usr --with-enchant=shared,/usr --enable-fpm --with-fpm-user=nginx --with-fpm-group=nginx --enable-zip --with-libzip --with-gdbm=/usr --enable-dba=shared --enable-xdebug=shared --enable-apcu=shared --enable-dtrace
make
make install

# initial default setting and init script
cp php.ini-development /etc/php.ini
cp php.ini-production /etc/php-fpm.ini
cp ./sapi/fpm/php-fpm.conf /etc/php-fpm.conf
cp ./sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm
chmod +x /etc/init.d/php-fpm
sed -i "/php_opts=.*$/aphp_opts=\$php_opts\" -c /etc/php-fpm.ini\"" /etc/init.d/php-fpm
mkdir /etc/php.d

# add shared module
ext_dir=`php-config | grep extension | sed "s/[]\[]//g" | awk '{print $2}'`;
cd $ext_dir
zend_ext=(opcache.so xdebug.so); 
for ext_name in `ls -l *.so | awk '{print $8}'` ; do 
    ini_name=${ext_name//.so/}.ini; 
    case "${zend_ext[@]}" in  
        *$ext_name*) echo "zend_extension=$ext_name" > /etc/php.d/$ini_name;; 
        *) echo "extension=$ext_name" > /etc/php.d/$ini_name;; 
    esac 
done

# compile php finished
cd $WORKING_DIR


######################################
#                                    #  
#  Optimize nginx and php configure  #
#                                    #
######################################

# optimize php.ini
# enable opcache
sed -i 's/^.*opcache.enable=.*$/opcache.enable = 1/g' /etc/php-fpm.ini
# set timezone
sed -i "s#;date.timezone =#date.timezone = Asia/Taipei#g" /etc/php-fpm.ini
sed -i "s#;date.timezone =#date.timezone = Asia/Taipei#g" /etc/php.ini
# expose set off
sed -i "s/^.*expose_php = .*$/expose_php = Off/g" /etc/php-fpm.ini
mkdir /var/log/php-fpm
# set php error log
sed -i "/^.*error_log = syslog.*$/aerror_log = /var/log/php-fpm/php_error.log" /etc/php-fpm.ini
# set disable functions
sed -i "s/^.*disable_functions =.*$/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,show_source/g" /etc/php-fpm.ini
# set open basedir to document root and tmp directory
sed -i 's#^.*open_basedir =.*$#open_basedir = /var/www:/tmp#g' /etc/php-fpm.ini
# add cache size
sed -i "s/^.*realpath_cache_size =.*$/realpath_cache_size = 4096k/" /etc/php-fpm.ini
sed -i "s/^.*realpath_cache_ttl =.*$/realpath_cache_ttl = 7200/" /etc/php-fpm.ini
# disable xdebug
mv /etc/php.d/xdebug.ini /etc/php.d/xdebug.ini.disable
# disable snmp
mv /etc/php.d/snmp.ini /etc/php.d/snmp.ini.disable

# optimize php-fpm
# set php-fpm error log
sed -i 's#^.*error_log =.*$#error_log = /var/log/php-fpm/fpm_error.log#g' /etc/php-fpm.conf
# listen through socket
sed -i "s/listen = 127.0.0.1:9000/;listen = 127.0.0.1:9000/g" /etc/php-fpm.conf
sed -i "/listen = 127.0.0.1:9000/alisten = /var/run/php5-fpm.sock\nlisten.owner = nginx\nlisten.group = nginx\nlisten.mode = 0666" /etc/php-fpm.conf
# add slow log
sed -i 's/^.*request_slowlog_timeout =.*$/request_slowlog_timeout = 15s/g' /etc/php-fpm.conf
sed -i 's#^.*slowlog =.*$#slowlog = /var/log/php-fpm/fpm-slow.log#g' /etc/php-fpm.conf
sed -i "s/^.*security.limit_extensions =.*$/security.limit_extensions = .php/g" /etc/php-fpm.conf
sed -i "s/^.*emergency_restart_threshold =.*$/emergency_restart_threshold = 10/g" /etc/php-fpm.conf
sed -i "s/^.*emergency_restart_interval =.*$/emergency_restart_interval = 1m/g" /etc/php-fpm.conf
sed -i "s/^.*process_control_timeout =.*$/process_control_timeout = 10s/g" /etc/php-fpm.conf

# configure nginx
# make conf.d directory
mkdir /etc/nginx/conf.d

# make virtual host dir
mkdir /etc/nginx/sites-available
mkdir /etc/nginx/sites-enabled

# copy nginx configure files
rsync -rv --exclude=default.conf config/nginx/*.conf /etc/nginx

# copy default virtual host site config
cp config/nginx/default.conf /etc/nginx/sites-available
ln -s /etc/nginx/sites-available/default.conf /etc/nginx/sites-enabled/default.conf



#####################
#                   #  
#  install mariaDB  #
#                   #
#####################

cat <<EOT >> /etc/yum.repos.d/MariaDB.repo
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.0/centos6-amd64
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1
EOT
yum -y install MariaDB-server MariaDB-client
mv /etc/my.cnf /etc/my.cnf.back
cp /usr/share/mysql/my-small.cnf /etc/my.cnf


#####################
#                   #  
#  install postfix  #
#                   #
#####################

yum -y install postfix opendkim libopendkim

# configure for local only
sed -i /^.*myhostname.*=.*virtual.*$/amyhostname\ =\ $MAIL_HOSTNAME /etc/postfix/main.cf
sed -i /^.*mydomain.*=.*$/amydomain\ =\ $MAIL_DOMAIN /etc/postfix/main.cf 
sed -i "s/^.*myorigin.*=.*\$myhostname.*$/myorigin = \$myhostname/g" /etc/postfix/main.cf
sed -i "s/^.*relay_domains.*=.*\$mydestination/relay_domains = \$mydestination/g" /etc/postfix/main.cf

# setup opendkim
sed -i 's#^.*Mode.*$#Mode sv#g' /etc/opendkim.conf
sed -i 's#^.*KeyFile.*/etc.*$#KeyFile /etc/opendkim/keys/my.private#g' /etc/opendkim.conf
sed -i "s/^.*Domain\s.*$/Domain = $MAIL_DOMAIN/g" /etc/opendkim.conf
sed -i 's#^.*KeyTable[\t\s].*$#KeyTable  refile:/etc/opendkim/KeyTable #g' /etc/opendkim.conf
sed -i 's#^.*SigningTable[\t\s].*$#SigningTable refile:/etc/opendkim/SigningTable#g' /etc/opendkim.conf
sed -i 's#^.*ExternalIgnoreList[\t\s].*$#ExternalIgnoreList refile:/etc/opendkim/TrustedHosts#g' /etc/opendkim.conf
sed -i 's#^.*InternalHosts[\t\s].*$#InternalHosts refile:/etc/opendkim/TrustedHosts#g' /etc/opendkim.conf

# KeyTable
echo "default._domainkey.$MAIL_DOMAIN $MAIL_DOMAIN:default:/etc/opendkim/keys/my.private" >> /etc/opendkim/KeyTable
echo "default._domainkey.$MAIL_HOSTNAME $MAIL_DOMAIN:default:/etc/opendkim/keys/my.private" >> /etc/opendkim/KeyTable

# SigningTable
echo "*@$MAIL_DOMAIN default._domainkey.$MAIL_DOMAIN" >> /etc/opendkim/SigningTable
echo "*@$MAIL_HOSTNAME default._domainkey.$MAIL_HOSTNAME" >> /etc/opendkim/SigningTable

# TrustedHosts
echo $MAIL_DOMAIN >> /etc/opendkim/TrustedHosts
echo $MAIL_HOSTNAME >> /etc/opendkim/TrustedHosts

# generate key
openssl genrsa -out /etc/opendkim/keys/my.private 1024
openssl rsa -in /etc/opendkim/keys/my.private -out /etc/opendkim/keys/my.public -pubout -outform PEM
chown opendkim:opendkim /etc/opendkim/keys/my.*
chmod 600 /etc/opendkim/keys/my.private
chmod 644 /etc/opendkim/keys/my.public

# dkim add to postfix
cat <<EOT >> /etc/postfix/main.cf
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
milter_default_action = accept
EOT

#
# ._domainkey.iphpo.com.    IN  TXT    "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqdYjgx2vIL4uxuPzFHzUF9THdQPkzDDCu7+0VMldoPhFdXA+pqhX4ndxVAkQOQ8R5HBb9Wu/rPvns7PbVz/2l+BvAi/Q8NqPDN1qYQgDHtgWtMz9CzBSqTdegERdlpblVfHKkFUrTVQGwYq7k4aFpxE52yhLgTQqDIeo82L9u8wIDAQAB"
# default._domainkey.iphpo.com.    IN  TXT    "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqdYjgx2vIL4uxuPzFHzUF9THdQPkzDDCu7+0VMldoPhFdXA+pqhX4ndxVAkQOQ8R5HBb9Wu/rPvns7PbVz/2l+BvAi/Q8NqPDN1qYQgDHtgWtMz9CzBSqTdegERdlpblVfHKkFUrTVQGwYq7k4aFpxE52yhLgTQqDIeo82L9u8wIDAQAB"
#

# install dk-milter
#mkdir /usr/man
#mkdir /usr/man/man3
#mkdir /usr/man/man8
#wget -O dk-milter-1.0.2.tar.gz --no-http-keep-alive "http://downloads.sourceforge.net/project/dk-milter/DomainKeys%20Milter/1.0.2/dk-milter-1.0.2.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fdk-milter%2F&ts=1428995065&use_mirror=nchc"
#tar zxvf dk-milter-1.0.2.tar.gz
#cd dk-milter-1.0.2
#sh Build -c
#sh Build install
#/usr/bin/dk-filter -l -b sv -p inet:8892@localhost -d $MAIL_DOMAIN -H -s /etc/opendkim/keys/my.private -S dk &



####################
#                  #  
#  setup iptables  #
#                  #
####################

# setup network core configure
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
for i in /proc/sys/net/ipv4/conf/*/{rp_filter,log_martians}; do
    echo "1" > $i
done
for i in /proc/sys/net/ipv4/conf/*/{accept_source_route,accept_redirects,send_redirects}; do
    echo "0" > $i
done

# clear old rules
$IPTABLE -F
$IPTABLE -X
$IPTABLE -Z

# set default policy
$IPTABLE -P INPUT DROP
$IPTABLE -P OUTPUT DROP
$IPTABLE -P FORWARD DROP

# allow all lo interface trafic
$IPTABLE -A INPUT -i lo -j ACCEPT
$IPTABLE -A OUTPUT -o lo -j ACCEPT

# allow state is RELATED, ESTABLISHED
$IPTABLE -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLE -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# drop all icmp packets
$IPTABLE -A INPUT -t icmp -j DROP

# open input ports
for port in $OPEN_INPUT_PORTS; do
    #$IPTABLE -A INPUT -p tcp -i $EXTINF --dport $port -j ACCEPT
    $IPTABLE -A INPUT -i $EXTINF -p tcp -s 0/0 --sport 1024:65535 --dport $port -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPTABLE -A OUTPUT -o $EXTINF -p tcp --sport $port -d 0/0 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
done

# open output ports
for port in $OPEN_OUTPUT_PORTS; do
    $IPTABLE -A OUTPUT -o $EXTINF -p tcp --dport $port -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPTABLE -A INPUT -i $EXTINF -p tcp --sport $port -m state --state ESTABLISHED -j ACCEPT
done

# open dns udp
$IPTABLE -A OUTPUT -p udp -o $EXTINF --dport 53 -j ACCEPT

# open ntp udp
$IPTABLE -A OUTPUT -p udp -o $EXTINF --dport 123 -j ACCEPT

# Drop sync
$IPTABLE -A INPUT -i $EXTINF -p tcp ! --syn -m state --state NEW -j DROP

# Drop Fragments
$IPTABLE -A INPUT -i $EXTINF -f -j DROP
 
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags ALL ALL -j DROP
 
# Drop NULL packets
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix " NULL Packets "
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags ALL NONE -j DROP
 
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
 
# Drop XMAS
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix " XMAS Packets "
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
 
# Drop FIN packet scans
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix " Fin Packets Scan "
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags FIN,ACK FIN -j DROP
 
$IPTABLE  -A INPUT -i $EXTINF -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# prevent DoS attack
$IPTABLE -A INPUT -i $EXTINF -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
$IPTABLE -N syn_flood
$IPTABLE -A INPUT -p tcp --syn -j syn_flood
$IPTABLE -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPTABLE -A syn_flood -j DROP

#Limiting the incoming icmp ping request:
#$IPTABLE -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IPTABLE -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
#$IPTABLE -A INPUT -p icmp -j DROP
#$IPTABLE -A OUTPUT -p icmp -j ACCEPT

/etc/init.d/iptables save


######################
#                    #  
#  install fail2ban  #
#                    #
######################

yum -y install fail2ban
sed -i "s/action.*=.*name=SSH.*$/action   = iptables[name=SSH, port=$SSHD_LISTEN_PORT, protocol=tcp]/g" /etc/fail2ban/jail.conf
sed -i "s/name=SSH.*dest=you@example.com/name=SSH, dest=$ALERT_EMAIL/g" /etc/fail2ban/jail.conf | grep name=SSH


####################
#                  #  
#  start services  #
#                  #
####################

# start nginx
/etc/init.d/nginx start
/sbin/chkconfig nginx on

# start php-fpm
/etc/init.d/php-fpm start
/sbin/chkconfig php-fpm on

# start mariadb
/etc/init.d/mysql start
/sbin/chkconfig mysql on

# start postfix
/etc/init.d/postfix start
/sbin/chkconfig postfix on

# start fail2ban
/etc/init.d/fail2ban start
/sbin/chkconfig fail2ban on

# start opendkim
/etc/init.d/opendkim start
/sbin/chkconfig opendkim on

#######################
#                     #  
#  configure mariadb  #
#                     #
#######################

mysql_secure_installation



#######################
#                     #  
#  print result info  #
#                     #
#######################
$DKIM_PUBLIC_KEY=`cat /etc/opendkim/keys/my.public`
echo "add _domainkey."$MAIL_DOMAIN" dns record: k=rsa; t=y; p="$DKIM_PUBLIC_KEY
echo "add default._domainkey."$MAIL_DOMAIN" dns record: k=rsa; t=y; p="$DKIM_PUBLIC_KEY


