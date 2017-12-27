#! /usr/bin/python

import sys, getopt, random, socket, os
from scapy.all import *
import ipaddress

DEFAULT_PORTS = [21,22,23,25,80,443]
SYN = 0x02
RST = 0x04
ACK = 0x10

def usage():
    print("usage: synprobe.py [-p port_range] target")
    print("port_range must be formated as an integer or an integer range. I.E. 'min-max'")

def format_address(ip,port):
    return ip+":"+str(port)

# GetOpt
try:
    opts, args = getopt.getopt(sys.argv[1:], "p:")
except getopt.GetoptError as err:
    print(err) 
    sys.exit(2)
if len(args) != 1:
    usage()
    sys.exit(2)

# Parse IP Input
ip_list = []
if "/" in args[0]:
    target_network = ipaddress.ip_network(args[0])
    for addr in target_network.hosts():
        ip_list.append(addr.exploded)
else:
    ip_list.append(args[0])

# Parse Port Input
port_list = DEFAULT_PORTS
if len(opts) > 0:
    try:
        port_string = opts[0][1]
        if "-" in port_string:
            port_range = port_string.split("-")
            if len(port_range) != 2:
                usage()
                sys.exit(2)
            port_list = range(int(port_range[0]), int(port_range[1]))
        else:
            port_list = [int(port_string)]
    except ValueError:
        usage()
        sys.exit(2)

# TCP SYN Scan
for target_ip in ip_list:
    for target_port in port_list:
        src_port = random.randint(1024,65535)
        ip_header = IP(dst=target_ip)
        syn_pkt = ip_header/TCP(sport=src_port,dport=target_port,flags="S")
        response = sr1(syn_pkt,timeout=5,verbose=False)
        if response == None:
            print(format_address(target_ip,target_port)+" got no reply.")
            continue
        resp_flags = response['TCP'].flags
        if resp_flags & SYN and resp_flags & ACK:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                sock.connect((target_ip,target_port))
                print("Connected to " + format_address(target_ip,target_port))
                response = sock.recv(1024)
                print("Target responded with...")
                hexdump(response)
            except socket.timeout:
                print("Target did not send any data on connection, probing with random bytes...")
                sock.send(os.urandom(1024))
                try:
                    response = sock.recv(1024)
                    print("Target responded with...")
                    hexdump(response)
                except socket.timeout:
                    print("Could not get target at "+format_address(target_ip,target_port)+" to respond, closing connection.")
                sock.close()
            except socket.herror:
                print("Could not connect to target at "+format_address(target_ip,target_port)+", most likely a bad address.")
        else:
            print("Target at "+format_address(target_ip, target_port)+" is closed.")
