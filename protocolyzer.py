from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

#TODO
secret_key = get_random_bytes(16) 
public_key = get_random_bytes(16)
private_key = get_random_bytes(32) 
#TODO

class Message:
    def __init(self,version=1,type=1,len=4,seq=1,timestamp=1,max=1,slice=0,padding=0,data):
        self.version = version
        self.type = type
        self.len = len
        self.seq = seq
        self.timestamp = timestamp
        self.max = max
        self.slice = slice
        self.data = data
        self.padding = padding
 
    def calculateMAC(self):
        h = HMAC.new(secret_key,digestmod=SHA256)
        h.update(bytearray)
        return h.hexdigest()
        #Mint kiderült ez nem kell, mert a EAX mód alapból használ mac-et, ami a tag-be kerül
 
    def convert_to_bytes(self):
        bytearray =  bytes(version,'utf-8')+bytes(type,'utf-8')+bytes(len,'utf-8')+bytes(seq,'utf-8')+bytes(timestamp,'utf-8')+bytes(max,'utf-8')+bytes(slice,'utf-8')+bytes(data,'utf-8')+bytes(padding,'utf-8')
        return bytearray
    
    def message_from_bytes(self,bytearray):
        #Na itt kell valami magic, fontos, hogy melyik változó hány bites

class Protocolyzer:
    def __init__(self, key):
        self.key = key

    def protocolyze(self,message):
        cipher = AES.new(self.key,AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(message.convert_to_bytes())
        return cipher.nonce,tag,cipher_text

    def deprotocolyze(self,nonce,tag,cipher_text)
        cipher = AES.new(key,AES.MODE_EAX,nonce)
        data = cipher.decrypt_and_verify(cipher_text,tag)
        return message_from_bytes(data)

