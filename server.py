from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os, sys, getopt, time
from netinterface import network_interface
from protocolyzer import Protocolyzer
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

class User:
    def __init__(self,id,password_hash):
        self.id = id
        self.password_hash = password_hash

def load_users(file):
    f = open(file,'r')
    temp_users = []
    for line in f:
        strings = line.split()
        temp_users.append(User(strings[0],strings[1]))
    return temp_users

NET_PATH = './'
OWN_ADDR = 'B'
users = load_users('users.txt')
state = "no_connection"
private_key = RSA.import_key(open("private.pem").read())



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

def find_user(id,password):
	for u in users:
		if u.id == received_id and u.password_hash == SHA256.new(data=password).hexdigest():
			return True
	return False

def wait_for_msg():
    status = False
    i = 0
    while not status and i < 5:
        status, msg = netint.receive_msg(blocking=False)
        i += 1
        time.sleep(0.5)
    return status, msg

def current_time():
	return str(time.strftime("%H:%M:%S", time.localtime()))+str(" : ")

# main loop
netint = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')
while True:
	if state == "no_connection":
		status,msg = wait_for_msg()
		if status:
			print(current_time()+"RSA coded msg received")
			cipher_rsa = PKCS1_OAEP.new(private_key)
			global session_key
			session_key = cipher_rsa.decrypt(msg)
			print(current_time()+"Session key: "+str(session_key))
			global proto
			proto = Protocolyzer(session_key)
			respone_msg = Message(data=bytes("ok",'utf-8'),type=2)
			netint.send_msg('A', proto.protocolyze(respone_msg))
			print(current_time()+"Auth response sent to 'A' client")
			state = "valid_sessionkey"
	if state == "valid_sessionkey":
		status,msg = wait_for_msg()
		if status:
			decoded_msg = proto.deprotocolyze(msg)
			if decoded_msg.type == 3:
				received_id = decoded_msg.data.decode('utf-8')
				print(current_time()+"Received id: "+str(received_id))
				ack_msg = Message(data=bytes("ok",'utf-8'),type=5)
				netint.send_msg(('A'), proto.protocolyze(ack_msg))
				status,msg = wait_for_msg()
				if status:
					received_pw = proto.deprotocolyze(msg).data
					print(current_time()+"Received password: "+str(received_pw))
					if find_user(received_id, received_pw):
							print(current_time()+"User "+received_id+" logged in.")
					else:
						print(current_time()+"Wrong id or password.")
						
							


    
