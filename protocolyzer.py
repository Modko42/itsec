from Crypto.Cipher import AES

class Message:
    def __init(self,version=1,type=1,len=4,seq=1,timestamp=1,max=1,slice=0,data,padding=0):
        self.version = version
        self.type = type
        self.len = len
        self.seq = seq
        self.timestamp = timestamp
        self.max = max
        self.slice = slice
        self.data = data
        self.padding = padding
    def convert_to_bytes():
        return bytes(version,'utf-8')+bytes(type,'utf-8')+bytes(len,'utf-8')+bytes(seq,'utf-8')+
        bytes(timestamp,'utf-8')+bytes(max,'utf-8')+bytes(slice,'utf-8')+bytes(data,'utf-8')+bytes(padding,'utf-8')

class Protocolyzer:
    def __init__(self, key):
        self.key = key

    def protocolyze(message):
        cipher = AES.new(self.key,AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest()

    def undedo_protocolyze()