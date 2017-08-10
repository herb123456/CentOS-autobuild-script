#!/bin/bash

source variable.sh

#install postfix

yum install -y postfix

sed -ie '/^#myhostname = virtual.domain.tld$/amyhostname = mail.iphpo.com' /etc/postfix/main.cf
sed -ie '/^#mydomain = domain.tld$/amydomain = iphpo.com' /etc/postfix/main.cf
sed -ie '/^#myorigin = \$mydomain$/amyorigin = $myhostname' /etc/postfix/main.cf
sed -ie 's/^inet_interfaces = localhost$/inet_interfaces = all/g' /etc/postfix/main.cf
sed -ie 's/^#relay_domains = $mydestination$/relay_domains = $mydestination/g' /etc/postfix/main.cf

cat <<EOT>> /etc/postfix/main.cf
virtual_alias_domains = iphpo.com mail.iphpo.com
virtual_alias_maps = hash:/etc/postfix/virtual

#TLS
smtp_use_tls = yes
smtpd_use_tls = yes
smtp_tls_note_starttls_offer = yes
smtpd_tls_auth_only = yes
smtpd_tls_key_file = /etc/letsencrypt/live/iphpo.com/privkey.pem
smtpd_tls_cert_file = /etc/letsencrypt/live/iphpo.com/cert.pem
smtpd_tls_CAfile    = /etc/letsencrypt/live/iphpo.com/chain.pem
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
tls_random_source = dev:/dev/urandom

# Disable SSL v2 & v3
#smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3
#smtp_tls_mandatory_protocols=!SSLv2,!SSLv3
#smtpd_tls_protocols=!SSLv2,!SSLv3
#smtp_tls_protocols=!SSLv2,!SSLv3
EOT

cat <<EOT>> /etc/postfix/virtual
@iphpo.com herb123456@gmail.com
@mail.iphpo.com herb123456@gmail.com herb963852@yahoo.com.tw
EOT


postmap /etc/postfix/virtual

systemctl start postfix.service