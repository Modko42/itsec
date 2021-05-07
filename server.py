import getopt
import os
import sys
import time
from getpass import getpass
from os import walk
from re import match

import Crypto
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from netinterface import network_interface
from protocolyzer import Message, Protocolyzer


class User:
    def __init__(self, id, password_hash):
        self.id = id
        self.password_hash = password_hash


def load_users(file):
    f = open(file, 'r')
    temp_users = []
    for line in f:
        strings = line.split()
        temp_users.append(User(strings[0], strings[1]))
    return temp_users


NET_PATH = './'
OWN_ADDR = 'B'
users = load_users('users.txt')
state = "no_connection"
private_key = RSA.import_key(open("private.pem").read())
global active_user
global proto
timeouttimestamp = time.time()

current_path = "./"


def get_ls(directory):
    list = ""
    for (dirpath, dirnames, filenames) in walk(directory):
        for l in (dirnames + filenames):
            list += (str(l) + "\n")
    if len(list) > 0:
        list = list[:-1]
    return list


try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
    print('Usage: python receiver.py -p <network path> -a <own addr>')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python receiver.py -p <network path> -a <own addr>')
        sys.exit(0)
    elif opt == '-p' or opt == '--path':
        NET_PATH = arg
    elif opt == '-a' or opt == '--addr':
        OWN_ADDR = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
    print('Error: Cannot access path ' + NET_PATH)
    sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
    print('Error: Invalid address ' + OWN_ADDR)
    sys.exit(1)


def find_user(id, password):
    for u in users:
        if u.id == received_id and u.password_hash == SHA256.new(data=password).hexdigest():
            return True
    return False


def wait_for_msg():
    status = False
    i = 0
    while not status and i < 10:
        status, msg = netint.receive_msg(blocking=False)
        i += 1
        time.sleep(0.2)
    return status, msg


def current_time():
    return str(time.strftime("%H:%M:%S", time.localtime())) + str(" : ")


def upload(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    lines_str = ""
    for l in lines:
        lines_str += l
    message_data = Message(data=bytes(lines_str,'utf-8'), type=7)
    print(message_data.type)
    netint.send_msg('A', proto.protocolyze(message_data))


def download(filename):
    status, result = wait_for_msg()
    msg = proto.deprotocolyze(result)
    if not status:
        return False
    with open(current_path + "/" + filename, 'w+') as f:
        for line in list(msg.data.decode('utf-8')):
            f.write(line)
    f.close()
    return True

# main loop
netint = network_interface(NET_PATH, OWN_ADDR)
print(current_time() + 'Server started.')
while True:
    if state == "no_connection":
        valid_msg=True
        status, msg = wait_for_msg()
        if status:
            print(current_time() + "RSA coded msg received")
            cipher_rsa = PKCS1_OAEP.new(private_key)
            global session_key
            try:
                session_key = cipher_rsa.decrypt(msg)
            except:
                valid_msg=False
                timeout_msg=Message(data=bytes("Connection timed out", 'utf-8'), type=8)
                netint.send_msg('A', proto.protocolyze(timeout_msg))
                print(current_time() + "Timeout notification sent to 'A' client")
            if(valid_msg):
                print(current_time() + "Session key: " + str(session_key))
                proto = Protocolyzer(session_key)
                respone_msg = Message(data=bytes("ok", 'utf-8'), type=2)
                netint.send_msg('A', proto.protocolyze(respone_msg))
                print(current_time() + "Auth response sent to 'A' client")
                state = "valid_sessionkey"
    elif state == "valid_sessionkey":
        status, msg = wait_for_msg()
        if status:
            decoded_msg = proto.deprotocolyze(msg)
            if decoded_msg.type == 3:
                received_id = decoded_msg.data.decode('utf-8')
                print(current_time() + "Received id: " + str(received_id))
                ack_msg = Message(data=bytes("ok", 'utf-8'), type=5)
                netint.send_msg(('A'), proto.protocolyze(ack_msg))
                status, msg = wait_for_msg()
                if status:
                    received_pw = proto.deprotocolyze(msg).data
                    print(current_time() + "Received password: " + str(received_pw))
                    if find_user(received_id, received_pw):
                        state = "user_logged_in"
                        timeouttimestamp = time.time()
                        active_user = str(received_id)
                        print(current_time() + "User " + active_user + " logged in.")
                        # update the current dir to match the user
                        current_path += active_user+"/"
                    else:
                        print(current_time() + "Wrong id or password.")

    elif state == "user_logged_in":
        status, msg = wait_for_msg()
        if status:
            timeouttimestamp=time.time()
            decoded_msg = proto.deprotocolyze(msg)
            split = decoded_msg.data.decode('utf-8').split()
            if decoded_msg.type == 6:
                if split[0] == "ls":
                    print(current_path)
                    result_msg = Message(data=bytes(get_ls(current_path), 'utf-8'), type=7)
                    print(get_ls(current_path))
                    netint.send_msg('A', proto.protocolyze(result_msg))
                    print(current_time() + "List of directories and files sent to 'A' client.")
                elif split[0] == "gwd":
                    result_msg = Message(data=bytes(current_path, 'utf-8'), type=7)
                    netint.send_msg('A', proto.protocolyze(result_msg))
                    print(current_time() + "Current directory name sent to 'A' client.")
                elif split[0] == "mkd":
                    if split[1] in get_ls(current_path):
                        result_msg = Message(data=bytes("Error, the directory already exists", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "Directory exists, error message sent to 'A' client.")
                    else:
                        os.mkdir(current_path + "/" + split[1])
                        result_msg = Message(data=bytes("Directory created", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "Current directory name sent to 'A' client.")
                elif split[0] == "rmd":
                    if split[1] not in get_ls(current_path):
                        result_msg = Message(data=bytes("Error, the directory doesn't exist", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "Directory doesn't exist, error message sent to 'A' client.")
                    else:
                        os.rmdir(current_path + "/" + split[1])
                        result_msg = Message(data=bytes("Directory deleted", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "Directory deleted, confirmation sent to 'A' client.")
                elif split[0] == "cwd":
                    if split[1] == "..":
                        split_dir = current_path.split("/")
                        current_path = "./" + active_user + "/"
                        for directory in split_dir[:-1]:
                            current_path += directory
                            current_path += "/"
                    elif split[1] not in get_ls(current_path):
                        result_msg = Message(data=bytes("Error, the directory doesn't exist", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "Directory doesn't exist, error message sent to 'A' client.")
                    else:
                        current_path += (split[1] + "/")
                        result_msg = Message(data=bytes("Current directory changed", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "Directory changed, confirmation sent to 'A' client.")
                elif split[0] == "rmf":
                    if split[1] not in get_ls(current_path):
                        result_msg = Message(data=bytes("Error, the file doesn't exist", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "File doesn't exist, error message sent to 'A' client.")
                    else:
                        os.remove(current_path + "/" + split[1])
                        result_msg = Message(data=bytes("File deleted", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "File deleted, confirmation sent to 'A' client.")
                elif split[0] == "download":
                    if split[1] not in get_ls(current_path):
                        result_msg = Message(data=bytes("Error, the file doesn't exist", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "File doesn't exist, error message sent to 'A' client.")
                    else:
                        upload(current_path + "/" + split[1])
                        print(current_time() + "File sent to 'A' client.")
                elif split[0] == "upload":
                    if split[1] in get_ls(current_path):
                        result_msg = Message(data=bytes("Error, the file already exists", 'utf-8'), type=7)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        print(current_time() + "File already exists, error message sent to 'A' client.")
                    else:
                        result_msg = Message(data=bytes("ok",'utf-8'),type=5)
                        netint.send_msg('A', proto.protocolyze(result_msg))
                        download(split[1])
                        print(current_time() + "File received from 'A' client.")
                        netint.send_msg('A', proto.protocolyze(result_msg))
            else:
                print(current_time() + "Unexpected message received.")
        else:
            print(str(time.time()-timeouttimestamp))
            if(time.time()-timeouttimestamp >= 60):
                state = "no_connection"

            
