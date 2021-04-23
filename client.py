import Crypto
from netinterface import network_interface
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from protocolyzer import Protocolyzer
from protocolyzer import Message
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


NET_PATH = './'
OWN_ADDR = 'A'
netint = network_interface(NET_PATH, OWN_ADDR)
public_key = RSA.generate(2048)
rsa_key = RSA.generate(2048)

key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("public.pem", "wb")
file_out.write(public_key)
file_out.close()

#Csak teszteléshez van
proto = Protocolyzer(b"\x88'\xbb>\x87\x05\xb2\xb0\xdee\x0c\x00\x99\x92*\xb9")
#Ez

def init_connection():
    #all the steps required to set up the secure channel between the client and server
    #generate custom key
    #encrypt the public key with it
    recipient_key = RSA.import_key(open("public.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    

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

def test():
    print("What the message?")
    message = Message(data=bytes(input(),'utf-8'))
    print("Sent: "+str(proto.protocolyze(message)))
    netint.send_msg('B',proto.protocolyze(message))

test()