#! /usr/bin/python

import sys,os,re,getopt,subprocess
from scapy.all import *

def arp_watch(pkt):
    return_string = None
    source_ip = pkt[0].psrc
    source_mac = pkt[0].hwsrc
    if source_ip not in arp_table:
        return_string = 'Just learned about host {} with MAC {}.'.format(source_ip,source_mac)
    elif arp_table[source_ip] != source_mac and pkt[0].op == 2:
        return_string = 'WARNING: {} has changed its MAC from {} to {}.'.format(source_ip,arp_table[source_ip],source_mac)
    arp_table[source_ip] = source_mac
    return return_string


# GetOpt
try:
    opts, args = getopt.getopt(sys.argv[1:], "i:")
except getopt.GetoptError as err:
    print(err)
    sys.exit(2)

# Get Interface name
interface = "eth0"
if len(opts) != 0:
    interface = opts[0][1]

# Validate Interface
if interface not in os.listdir('/sys/class/net/'):
    print("Invalid interface: {}".format(interface))
    sys.exit(2)

# Get current ARP table
arp_output = subprocess.check_output(["arp","-n","-i",interface]).split()

# Parse ARP Table
arp_table = {}
ip_pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
for i in range(0,len(arp_output)):
    if ip_pat.match(arp_output[i]):
        arp_table[arp_output[i]] = arp_output[i+2]

# Monitor for ARP Messages
print("Monitoring ARP messages, will give a WARNING when a host announces a change in its MAC address.")
sniff(prn=arp_watch, filter='arp', count=0)
