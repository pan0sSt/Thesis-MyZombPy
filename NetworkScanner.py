#!/usr/bin/env python

import scapy.all as scapy
import re
import multiprocessing


def broadcast(ip):
    arp_request = scapy.ARP(pdst=ip)
    brdcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = brdcast / arp_request
    return scapy.srp(arp_request_broadcast, timeout=2, retry=3, verbose=False)[0]


def scan(scan_ip, network_results):
    network_results.append([ip[1].psrc for ip in broadcast(scan_ip)])


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
