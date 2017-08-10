#!/bin/bash

# install epel
rpm -iv https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# install remi
rpm -iv http://remi.mirrors.arminco.com/enterprise/remi-release-7.rpm

# update yum
yum -y update
yum -y upgrade