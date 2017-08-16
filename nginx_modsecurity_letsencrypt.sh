#!/bin/bash

source variable.sh

# Compile nginx with mod_security
yum install -y git wget gcc gcc-c++ pcre-devel zlib-devel openssl openssl-devel httpd-devel libxml2-devel xz-devel python-devel libcurl-devel libxslt-devel gd gd-devel gmp gmp-devel perl-Tk-devel perl-ExtUtils-Embed.noarch GeoIP GeoIP-devel gperftools gperftools-devel
yum groupinstall -y 'Development Tools' 

# wget https://www.modsecurity.org/tarball/2.9.1/modsecurity-$MOD_VERSION.tar.gz
wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
wget https://www.openssl.org/source/openssl-1.0.2-latest.tar.gz

# tar zxvf modsecurity-$MOD_VERSION.tar.gz
tar zxvf nginx-$NGINX_VERSION.tar.gz
tar zxvf openssl-1.0.2-latest.tar.gz

git clone https://github.com/SpiderLabs/ModSecurity.git modsecurity-$MOD_VERSION
cd modsecurity-$MOD_VERSION
./autogen.sh
./configure --enable-standalone-module --disable-mlogc
make
make install

cd ..

cd nginx-$NGINX_VERSION
sed -i "s/Server: nginx/Server: Hello/g" src/http/ngx_http_header_filter_module.c
./configure --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_geoip_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic' --add-module=../modsecurity-$MOD_VERSION/nginx/modsecurity --with-openssl=../openssl-1.0.2l

make
make install

adduser --no-create-home --user-group -s /sbin/nologin nginx
mkdir /var/lib/nginx
mkdir /var/lib/nginx/tmp
chown -R nginx:nginx /var/lib/nginx

/bin/cat <<EOM >/usr/lib/systemd/system/nginx.service
[Unit]
Description=The nginx HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
# Nginx will fail to start if /run/nginx.pid already exists but has the wrong
# SELinux context. This might happen when running `nginx -t` from the cmdline.
# https://bugzilla.redhat.com/show_bug.cgi?id=1268621
ExecStartPre=/usr/bin/rm -f /run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP \$MAINPID
KillSignal=SIGQUIT
TimeoutStopSec=5
KillMode=process
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOM

systemctl daemon-reload

mkdir /etc/nginx/conf.d
mkdir /etc/nginx/sites-available
mkdir /etc/nginx/sites-enabled

cd ..

cp modsecurity-$MOD_VERSION/modsecurity.conf-recommended /etc/nginx/modsecurity.conf
cp modsecurity-$MOD_VERSION/unicode.mapping /etc/nginx
sed -ie 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/nginx/modsecurity.conf
sed -ie 's/SecPcreMatchLimit .*$/SecPcreMatchLimit 150000/g' /etc/nginx/modsecurity.conf
sed -ie 's/SecPcreMatchLimitRecursion .*$/SecPcreMatchLimitRecursion 150000/g' /etc/nginx/modsecurity.conf
sed -ie 's/SecAuditLogType Serial/SecAuditLogType Concurrent/g' /etc/nginx/modsecurity.conf
sed -ie "/^SecAuditLogType Concurrent$/aSecAuditLogStorageDir \/var\/log\/nginx" /etc/nginx/modsecurity.conf
cat <<EOT >> /etc/nginx/modsecurity.conf
Include owasp-modsecurity-crs/crs-setup.conf
Include owasp-modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf
Include owasp-modsecurity-crs/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
Include owasp-modsecurity-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include owasp-modsecurity-crs/rules/REQUEST-912-DOS-PROTECTION.conf
Include owasp-modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf
Include owasp-modsecurity-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include owasp-modsecurity-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include owasp-modsecurity-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include owasp-modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include owasp-modsecurity-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include owasp-modsecurity-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
Include owasp-modsecurity-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
EOT

git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
mv owasp-modsecurity-crs /etc/nginx
cd /etc/nginx/owasp-modsecurity-crs
cp crs-setup.conf.example crs-setup.conf
sed -ie 's/SecDefaultAction "phase:1,log,auditlog,pass"/#SecDefaultAction "phase:1,log,auditlog,pass"/g' crs-setup.conf
sed -ie 's/SecDefaultAction "phase:2,log,auditlog,pass"/#SecDefaultAction "phase:2,log,auditlog,pass"/g' crs-setup.conf
sed -ie 's/#.*SecDefaultAction "phase:1,log,auditlog,deny,status:403"/SecDefaultAction "phase:1,log,auditlog,deny,status:403"/g' crs-setup.conf
sed -ie 's/# SecDefaultAction "phase:2,log,auditlog,deny,status:403"/SecDefaultAction "phase:2,log,auditlog,deny,status:403"/g' crs-setup.conf

# nginx.conf
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.back
cat <<EOT>> /etc/nginx/nginx.conf
user              nginx nginx;
worker_processes  1;

worker_rlimit_nofile 260000;
timer_resolution 100ms;

error_log    /var/log/nginx/nginx_error.log;


events {
    worker_connections  2048;
    accept_mutex on;
    accept_mutex_delay 100ms;
    use epoll;
    #multi_accept on;
}

http {

    # don't send the nginx version number in error pages and Server header
    server_tokens off;
     
    # config to don't allow the browser to render the page inside an frame or iframe
    # and avoid clickjacking http://en.wikipedia.org/wiki/Clickjacking
    # if you need to allow [i]frames, you can use SAMEORIGIN or even set an uri with ALLOW-FROM uri
    # https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options
    add_header X-Frame-Options SAMEORIGIN;
     
    # when serving user-supplied content, include a X-Content-Type-Options: nosniff header along with the Content-Type: header,
    # to disable content-type sniffing on some browsers.
    # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
    # currently suppoorted in IE > 8 http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx
    # http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx
    # 'soon' on Firefox https://bugzilla.mozilla.org/show_bug.cgi?id=471020
    add_header X-Content-Type-Options nosniff;
     
    # This header enables the Cross-site scripting (XSS) filter built into most recent web browsers.
    # It's usually enabled by default anyway, so the role of this header is to re-enable the filter for
    # this particular website if it was disabled by the user.
    # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
    add_header X-XSS-Protection "1; mode=block";
     
    # with Content Security Policy (CSP) enabled(and a browser that supports it(http://caniuse.com/#feat=contentsecuritypolicy),
    # you can tell the browser that it can only download content from the domains you explicitly allow
    # http://www.html5rocks.com/en/tutorials/security/content-security-policy/
    # https://www.owasp.org/index.php/Content_Security_Policy
    # I need to change our application code so we can increase security by disabling 'unsafe-inline' 'unsafe-eval'
    # directives for css and js(if you have inline css or js, you will need to keep it too).
    # more: http://www.html5rocks.com/en/tutorials/security/content-security-policy/#inline-code-considered-harmful
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com https://connect.facebook.net; img-src 'self' https://ssl.google-analytics.com https://s-static.ak.facebook.com ; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://themes.googleusercontent.com; frame-src https://www.facebook.com https://s-static.ak.facebook.com; object-src 'none'";
  

    #log_format      main    '\$remote_addr - \$remote_user [\$time_local] \$request '
    #                '"\$status" \$body_bytes_sent "\$http_referer" '
    #                '"\$http_user_agent" "\$http_x_forwarded_for" "\$gzip_ratio"'
    #                ' "\$connection" "\$connection_requests" "\$request_time"';



    index  index.php index.html index.htm;
    include       mime.types;
    default_type  application/octet-stream;
    charset utf-8;

    sendfile on;
    #sendfile_max_chunk 1m;
    tcp_nopush  on;
    tcp_nodelay on;
    server_name_in_redirect off;
    
    keepalive_timeout  10;
    keepalive_requests 100;
    lingering_time 20s;
    lingering_timeout 5s;
    keepalive_disable msie6;

    gzip on;
    gzip_vary   on;
    gzip_disable "MSIE [1-6]\.";
    gzip_static on;
    gzip_min_length   1400;
    gzip_buffers      32 8k;
    gzip_http_version 1.0;
    gzip_comp_level 5;
    gzip_proxied    any;
    gzip_types text/plain text/css text/xml application/javascript application/x-javascript application/xml application/xml+rss application/ecmascript application/json image/svg+xml;

    client_body_buffer_size 256k;
    client_body_in_file_only off;
    client_body_timeout 60s;
    client_header_buffer_size 64k;
    ## how long a connection has to complete sending 
    ## it's headers for request to be processed
    client_header_timeout  20s;
    client_max_body_size  20m; 
    connection_pool_size  512;
    
    #directio  4m;
    
    ignore_invalid_headers on;       
    large_client_header_buffers 8 64k;
    output_buffers   8 256k;
    postpone_output  1460;
    #proxy_temp_path  /tmp/nginx_proxy/;
    request_pool_size  32k;
    reset_timedout_connection on;
    send_timeout     60s;
    types_hash_max_size 2048;
    server_names_hash_bucket_size 64;

    # for nginx proxy backends to prevent redirects to backend port 
    # port_in_redirect off;

    open_file_cache max=10000 inactive=30s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;
    open_log_file_cache max=4096 inactive=30s min_uses=2;
    
    ### Directive describes the zone, in which the session states are stored i.e. store in slimits. ###
    ### 1m can handle 32000 sessions with 32 bytes/session, set to 5m x 32000 session ###
    limit_conn_zone \$binary_remote_addr zone=slimits:10m;
 
    ### Control maximum number of simultaneous connections for one session i.e. ###
    ### restricts the amount of connections from a single ip address ###
    limit_conn slimits 10;

    ## Load virtual host conf files. ##
    include /etc/nginx/sites-enabled/*;
     
    ## Load another configs from conf.d/ ##
    include /etc/nginx/conf.d/*.conf;
}
EOT

# default site config
touch /etc/nginx/sites-available/default.conf
cat <<EOT>> /etc/nginx/sites-available/default.conf
server {
    listen 80;
    server_name iphpo.com www.iphpo.com mail.iphpo.com;

    root   /var/www/html;

    access_log              /var/log/nginx/default.access.log;
    error_log               /var/log/nginx/default.error.log      error;

    location ~ /.well-known {
            allow all;
            break;
    }

    location / {

        index  index.php index.html index.htm;

        ModSecurityEnabled on;
        ModSecurityConfig /etc/nginx/modsecurity.conf;

        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }
}
EOT
ln -s /etc/nginx/sites-available/default.conf /etc/nginx/sites-enabled/default.conf
echo "hi" > /var/www/html/index.html

touch /etc/nginx/sites-available/blog.conf
cat <<EOT>> /etc/nginx/sites-available/blog.conf
server {
    listen 80;
    server_name blog.iphpo.com;

    root   /var/www/blog;

    access_log              /var/log/nginx/blog/access.log;
    error_log               /var/log/nginx/blog/error.log      error;

    location ~ /.well-known {
            allow all;
            break;
    }

    location / {

        index  index.php index.html index.htm;

        ModSecurityEnabled on;
        ModSecurityConfig /etc/nginx/modsecurity.conf;

        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }
}
EOT

mkdir /var/www/blog
mkdir /var/log/nginx/blog
ln -s /etc/nginx/sites-available/blog.conf /etc/nginx/sites-enabled/blog.conf

systemctl start nginx.service

# let’s encrypt

yum install -y certbot
certbot certonly --webroot -w /var/www/html -d iphpo.com -d www.iphpo.com -d mail.iphpo.com -w /var/www/blog -d blog.iphpo.com




cd $WORKING_DIR