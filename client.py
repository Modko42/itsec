import Crypto
from netinterface import network_interface
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from protocolyzer import Protocolyzer
from protocolyzer import Message
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from getpass import getpass
import time

NET_PATH = './'
OWN_ADDR = 'A'
netint = network_interface(NET_PATH, OWN_ADDR)
session_key = 0
state = 0

# Csak teszteléshez van
proto = Protocolyzer(b"\x88'\xbb>\x87\x05\xb2\xb0\xdee\x0c\x00\x99\x92*\xb9")


# Ez

def init_connection():
    # all the steps required to set up the secure channel between the client and server
    # generate custom key
    # encrypt the public key with it
    recipient_key = RSA.import_key(open("public.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    netint.send_msg('B', enc_session_key)
    return True


def get_login_data():
    print("Login process")
    print("Id: ", end='')
    id = input()
    print("Password: ", end='')
    passwd = getpass()  # Hides characters during input
    return id, passwd


def login():
    id, passwd = get_login_data()
    message_id = Message(data=bytes(id, 'utf-8'), type=3)
    netint.send_msg('B', proto.protocolyze(message_id))

    # salt = get_random_bytes(16)
    # file_key = PBKDF2(passwd, salt, 32, count=1000000, hmac_hash_module=SHA512)
    return True


def test():
    print("What the message?")
    message = Message(data=bytes(input(), 'utf-8'))
    print("Sent: " + str(proto.protocolyze(message)))
    netint.send_msg('B', proto.protocolyze(message))


def wait_for_msg():
    status = False
    i = 0
    while not status and i < 5:
        status, msg = netint.receive_msg(blocking=False)
        i += 1
        time.sleep(0.5)
    return status, msg


def upload(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    message_data = Message(data=bytes(lines), type=7)
    netint.send_msg('B', proto.protocolyze(message_data))
    status, result = proto.deprotocolyze(wait_for_msg())
    if status:
        if result.type == 5:
            return True
        else:
            return False


def download(filename):
    status, result = proto.deprotocolyze(wait_for_msg())
    if not status:
        return False
    with open(filename, 'w+') as f:
        for line in list(result.data):
            f.write(line)
    f.close()
    return True


def command():
    print("Type your command")
    cmd = input()
    split = cmd.split()
    if split[0] == "upload":
        message_command = Message(data=bytes(cmd, 'utf-8'), type=6)
        netint.send_msg('B', proto.protocolyze(message_command))

        if status:
            if result.type != 5:
                print("Error, no answer")
            else:
                if upload(split[1]):
                    print("Upload successful")
                else:
                    print("Upload failed")

    elif split[0] == "download":
        message_command = Message(data=bytes(cmd, 'utf-8'), type=6)
        netint.send_msg('B', proto.protocolyze(message_command))
        if download(split[1]):
            print("Download successful")
        else:
            print("Download failed")
    else:
        message_command = Message(data=bytes(cmd, 'utf-8'), type=6)
        netint.send_msg('B', proto.protocolyze(message_command))
        status, result = wait_for_msg()
        if status:
            print(proto.deprotocolyze(result))
        else:
            print("Timeout error")


while True:
    if state == 0:
        if init_connection():
            print("Connected successfully!")
            state = 1
    elif state == 1:
        if login():
            print("Successful login")
            state = 2
    elif state == 2:
        command()
