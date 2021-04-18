import Crypto
from netinterface import network_interface
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from protocolyzer import Protocolyzer


NET_PATH = './'
OWN_ADDR = 'A'
netint = network_interface(NET_PATH, OWN_ADDR)

def init_connection():
    #all the steps required to set up the secure channel between the client and server
    #generate custom key
    #encrypt the public key with it
    print('hello')
    proto = Protocolyzer()


def get_password():
    print("Please provide your password:")
    password = input()
    return password

def login():
    print("Starting login process...")
    passwd = get_password()
    netint.send_msg('B', proto.protocolyze(passwd))
    salt = get_random_bytes(16)
    file_key = PBKDF2(passwd, salt, 32, count=1000000, hmac_hash_module=SHA512)


login()