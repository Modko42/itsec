<<<<<<< HEAD
=======
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

>>>>>>> 284a1f523eb3a8c1deda4a5d69b7086a93870aad
class Protocolyzer:
    def __init__(self, key):
        self.key = key

    def protocolyze(message):
        print("Hello, I am protocolyzer")

    def undedo_protocolyze()