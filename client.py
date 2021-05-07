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

timeouttimestamp=time.time()-60
state = 0

def current_time():
	return str(time.strftime("%H:%M:%S", time.localtime()))+str(" : ")




def init_connection():
    recipient_key = RSA.import_key(open("public.pem").read())
    global session_key
    session_key = get_random_bytes(16)
    print(current_time()+"Session key: "+str(session_key))
    global proto
    proto = Protocolyzer(session_key)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    netint.send_msg('B', enc_session_key)
    status, result = wait_for_msg()
    if status:
        if proto.deprotocolyze(result).type == 2:
            return True
    return False
    


def get_login_data():
    print("Login process")
    print("Id: ", end='')
    id = input()
    passwd = getpass()  # Hides characters during input
    return id, passwd


def login():
    id, passwd = get_login_data()
    message_id = Message(data=bytes(id, 'utf-8'), type=3)
    message_pw = Message(data=bytes(passwd, 'utf-8'), type=4)
    netint.send_msg('B', proto.protocolyze(message_id))
    status,msg = wait_for_msg()
    if status:
        if proto.deprotocolyze(msg).type == 5:
            netint.send_msg('B', proto.protocolyze(message_pw))
    return status

def wait_for_msg():
    status = False
    i = 0
    while not status and i < 15:
        status, msg = netint.receive_msg(blocking=False)
        i += 1
        time.sleep(0.2)
    return status, msg


def upload(filename):
    global state
    global timeouttimestamp
    with open(filename, 'r') as f:
        lines = f.readlines()
    lines_str = ""
    for l in lines:
        lines_str += l
    message_data = Message(data=bytes(lines_str,'utf-8'), type=7)
    netint.send_msg('B', proto.protocolyze(message_data))
    status, result = wait_for_msg()
    if status:
        msg = proto.deprotocolyze(result)
        if msg.type == 5:
            return True
    print(current_time()+"Timeout error")
    timeouttimestamp=time.time()
    state=0
    return False


def download(filename):
    global state
    global timeouttimestamp
    status, result = wait_for_msg()
    if not status:
        print(current_time()+"Timeout error")
        timeouttimestamp=time.time()
        state=0
        return False
    msg = proto.deprotocolyze(result)
    if(msg.type == 8):
        print(current_time()+"Timeout error")
        timeouttimestamp=time.time()
        state=0
        return
    with open(filename, 'w+') as f:
        for line in list(msg.data.decode('utf-8')):
            f.write(line)
    f.close()
    return True


def command():
    global state
    global timeouttimestamp
    print("Type your command: ",end='')
    cmd = input()
    split = cmd.split()
    if split[0] == "upload":
        message_command = Message(data=bytes(cmd, 'utf-8'), type=6)
        netint.send_msg('B', proto.protocolyze(message_command))
        status,msg = wait_for_msg()
        result = proto.deprotocolyze(msg)
        if status:
            if result.type != 5:
                if(result.type == 8):
                    print(current_time()+"Timeout error")
                    timeouttimestamp=time.time()
                    state=0
                    return
                print(current_time()+result.data.decode('utf-8'))
            else:
                if upload(split[1]):
                    print(current_time()+"Upload successful")
                else:
                    print(current_time()+"Upload failed")
        else:
            print(current_time()+"Timeout error")
            timeouttimestamp=time.time()
            state=0

    elif split[0] == "download":
        message_command = Message(data=bytes(cmd, 'utf-8'), type=6)
        netint.send_msg('B', proto.protocolyze(message_command))
        if download(split[1]):
            print(current_time()+"Download successful")
        else:
            print(current_time()+"Download failed")
    else:
        message_command = Message(data=bytes(cmd, 'utf-8'), type=6)
        netint.send_msg('B', proto.protocolyze(message_command))
        status, result = wait_for_msg()
        msg=proto.deprotocolyze(result)
        if status:
            if(msg.type == 8):
                print(current_time()+"Timeout error")
                state=0
                return
            print(msg.data.decode("utf-8"))
        else:
            print(current_time()+"Timeout error")
            timeouttimestamp=time.time()
            state=0

while True:
    if state == 0:
        waittime=time.time()-timeouttimestamp
        print(waittime)
        if(waittime >= 60):
            if init_connection():
                print(current_time()+"Connected successfully!")
                state = 1
            else:
                print(current_time()+"Connection failed!")
        else:
            print(str(60-waittime) +"seconds till you can attempt to login")
            time.sleep(10)
    elif state == 1:
        if login():
            print(current_time()+"Successful login!")
            state = 2
        else:
            print(current_time()+"Login failed, wrong id or password!")
    elif state == 2:
        try:
            command()
        except:
            print("Error while communicating with the server, disconnecting")
            timeouttimestamp=time.time()
            state = 0
