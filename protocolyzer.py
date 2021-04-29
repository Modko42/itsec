from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from bitarray import bitarray
import time

#TODO
secret_key = get_random_bytes(16) 
public_key = get_random_bytes(16)
private_key = get_random_bytes(32) 
#TODO

class Message:
    def __init__(self,data,version=1,type=1,seq=1,timestamp=0,max=1,slice=1):
        self.version = version
        self.type = type
        self.len = len(data)
        self.seq = seq
        if timestamp == 0:
            self.timestamp = int(time.time())
        self.max = max
        self.slice = slice
        self.data = data
        self.padding = bitarray((1400 - self.len) * 8)
        self.padding.setall(0)
        self.padding[0] = 1
 
  
    def convert_to_bytes(self):
        bytearray = self.version.to_bytes(4,'big')+self.type.to_bytes(4,'big')+self.len.to_bytes(4,'big')+self.seq.to_bytes(20,'big')+self.timestamp.to_bytes(22,'big')+self.max.to_bytes(4,'big')+self.slice.to_bytes(4,'big')+bytes(self.data)+self.padding.tobytes()
        return bytearray

    def bytes_to_message(self,bytearray):
        ver = int.from_bytes(bytearray[:4],'big')
        typ = int.from_bytes(bytearray[4:8],'big')
        len = int.from_bytes(bytearray[8:12],'big')
        seq = int.from_bytes(bytearray[12:32],'big')
        timestamp = int.from_bytes(bytearray[32:54],'big')
        max = int.from_bytes(bytearray[54:58],'big')
        slice = int.from_bytes(bytearray[58:62],'big')
        data = bytearray[62:62+len]

        return Message(data,ver,typ,seq,timestamp,max,slice)

class Protocolyzer:
    def __init__(self, key):
        self.key = key

    def protocolyze(self,message):
        cipher = AES.new(self.key,AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(message.convert_to_bytes())
        return cipher.nonce+tag+cipher_text

    def deprotocolyze(self,string_array):
        ciphernonce = string_array[:16]
        tag = string_array[16:32]
        cipher_text = string_array[32:]

        cipher = AES.new(self.key,AES.MODE_EAX,ciphernonce)
        data = cipher.decrypt_and_verify(cipher_text,tag)
        return Message.bytes_to_message(self,bytearray = data)


