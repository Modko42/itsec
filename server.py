from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os, sys, getopt, time
from netinterface import network_interface
from protocolyzer import Protocolyzer

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
#Teszthez
proto = Protocolyzer(b"\x88'\xbb>\x87\x05\xb2\xb0\xdee\x0c\x00\x99\x92*\xb9")
#Van


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

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')
while True:
# Calling receive_msg() in non-blocking mode ... 
#	status, msg = netif.receive_msg(blocking=False)    
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message 
	print("Received message: "+str(msg))
	decoded_message = proto.deprotocolyze(msg)
	print(decoded_message.data)
    
