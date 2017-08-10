#!/bin/bash

# nginx config with SSL
echo "" > /etc/nginx/sites-available/default.conf
cat <<EOT>>/etc/nginx/sites-available/default.conf
server {
    listen 80;
    server_name iphpo.com www.iphpo.com mail.iphpo.com;

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2 default_server backlog=256;
    server_name iphpo.com www.iphpo.com mail.iphpo.com;
    root   /var/www/html;

    access_log              /var/log/nginx/default.access.log;
    error_log               /var/log/nginx/default.error.log      error;

    ssl_certificate /etc/letsencrypt/live/iphpo.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/iphpo.com/privkey.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';

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


# blog config
echo "" > /etc/nginx/sites-available/blog.conf
cat <<EOT>>/etc/nginx/sites-available/blog.conf
server {
    listen 80;
    server_name blog.iphpo.com;

    return 301 https://\$host\$request_uri;
}

server {
    listen  443 ssl http2;
    server_name blog.iphpo.com;
    root   /var/www/blog;

    access_log              /var/log/nginx/blog/access.log;
    error_log               /var/log/nginx/blog/error.log      error;

    ssl_certificate /etc/letsencrypt/live/iphpo.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/iphpo.com/privkey.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';

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

    location ~ .php\$ {
        fastcgi_pass   unix:/var/run/php71-fpm.sock;
        fastcgi_index  index.php;

        fastcgi_param   SCRIPT_FILENAME    \$document_root\$fastcgi_script_name;
        fastcgi_param   SCRIPT_NAME        \$fastcgi_script_name;

        fastcgi_buffer_size 128k;
        fastcgi_buffers 256 16k;
        fastcgi_busy_buffers_size 256k;
        fastcgi_temp_file_write_size 256k;


        include fastcgi_params;

    }

}
EOT

systemctl restart nginx