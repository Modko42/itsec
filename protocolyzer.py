from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

#TODO
secret_key = get_random_bytes(16) 
public_key = get_random_bytes(16)
private_key = get_random_bytes(32) 
#TODO

class Message:
    def __init__(self,data,version=2,type=1,seq=1,timestamp=11,max=4,slice=1,padding=10):
        self.version = version
        self.type = type
        self.len = len(data)
        self.seq = seq
        self.timestamp = timestamp
        self.max = max
        self.slice = slice
        self.data = data
        self.padding = padding
 
  
    def convert_to_bytes(self):
        bytearray = self.version.to_bytes(4,'big')+self.type.to_bytes(4,'big')+self.len.to_bytes(4,'big')+self.seq.to_bytes(20,'big')+self.timestamp.to_bytes(22,'big')+self.max.to_bytes(4,'big')+self.slice.to_bytes(4,'big')+bytes(self.data)+self.timestamp.to_bytes(10,'big')
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
        padding = int.from_bytes(bytearray[62+len:],'big')

        return Message(data,ver,typ,seq,timestamp,max,slice,padding)

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


