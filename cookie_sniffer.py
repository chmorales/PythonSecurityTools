#! /usr/bin/python

from scapy.all import *
from scapy.layers import http
import sys,getopt


def print_cookie_info(pkt):
    if pkt.haslayer(http.HTTPRequest):
        host = pkt['HTTPRequest'].Host
        cookie = pkt['HTTPRequest'].Cookie
        if host not in cookies:
            cookies[host] = cookie
            return "Host: {}, Cookie: {}".format(host,cookie)
        return None


# Keep track of seen cookies
cookies = {}

# Getopt
try:
    opts,args = getopt.getopt(sys.argv[1:], "i:")
except getopt.GetoptError as err:
    print(err)
    sys.exit(2)

# Assign interface
interface = "eth0"
if len(opts) != 0:
    interface = opts[0][1]

# Sniff
print("Starting to sniff on interface " + interface + "... CTRL-C to exit.")
sniff(iface=interface,prn=print_cookie_info,filter='tcp port 80',count=0)
