#!/bin/bash

source variable.sh

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
# $IPTABLE -A INPUT -t icmp -j DROP

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

/usr/libexec/iptables/iptables.init save
