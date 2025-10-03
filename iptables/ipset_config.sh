#!/bin/bash

#Scanners performing active scanning end up on this list
ipset create port_scanners hash:ip family inet hashsize 32768 maxelem 65535 timeout 900
#Any traffic that can't be classified as being a port scanner ends up in this group
ipset create scanned_ports hash:ip,port family inet hashsize 32768 maxelem 65535 timeout 900
#Sources of invalid traffic
ipset create invalid_scanners hash:ip family inet hashsize 32768 maxelem 65535 timeout 900
#This is going to be the same group of IP addresses from scanned_ports just without the port info.
ipset create other_scanners hash:ip family inet hashsize 32768 maxelem 65535 timeout 900