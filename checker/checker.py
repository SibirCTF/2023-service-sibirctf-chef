#!/usr/bin/python3
import socket, os, errno, sys, logging

class Client(object):
    def __init__(self, address, port):
        self.address = address
        self.port = port

    def connect(self, empty):
        self.s = socket.socket()
        self.s.connect((self.address, self.port))

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
    
    def DELE(self, empty):
        self.s.send(b"\x0E")
        return self.s.recv(0x40)

    def TERM(self, empty):
        self.s.send(b"\x0F")
        retval = self.s.recv(0x40)
        self.s.close()
        return retval

def service_up():
    print("UP 101")
    exit(101)
def service_corrupt():
    print("CORRUPT 102")
    exit(102)
def service_mumble():
    print("MUMBLE 103")
    exit(103)
def service_down():
    print("DOWN 104")
    exit(104)
def check_shit():
    print("CHECK SHIT")
    exit(0)

put_script = [
    ["AUTH", 0, [b"OP_AUTH_SUCCESS\x00", b"OP_LOAD_SUCCESS\x00"]],
    ["OPEN", 0, [b"OP_OPEN_SUCCESS\x00"]],
    ["WRTE", 0, [b"OP_WRTE_SUCCESS\x00"]],
    ["LOAD", 0, [b"OP_LOAD_SUCCESS\x00"]],
    ["SHFT", 0, [b"OP_SHFT_SUCCESS\x00"]],
    ["WRTE", 0, [b"OP_WRTE_SUCCESS\x00"]],
    ["WRTE", 0, [b"OP_WRTE_SUCCESS\x00"]],
    ["WRTE", 0, [b"OP_WRTE_SUCCESS\x00"]],
    ["SHFT", 0, [b"OP_SHFT_SUCCESS\x00"]],
    ["ENCD", 0, [b"OP_ENCD_SUCCESS\x00"]],
    ["DUMP", 0, [b"OP_DUMP_SUCCESS\x00"]],
    ["CLSE", 0, [b"OP_CLSE_SUCCESS\x00"]],
    ["SAVE", 0, [b"OP_SAVE_SUCCESS\x00"]],
    ["TERM", 1]
]
check_script = [
    ["AUTH", 0, [b"OP_AUTH_SUCCESS\x00", b"OP_LOAD_SUCCESS\x00"]],
    ["LIST", 1],
    ["OPEN", 0, [b"OP_OPEN_SUCCESS\x00"]],
    ["REST", 0, [b"OP_REST_SUCCESS\x00"]],
    ["SHFT", 0, [b"OP_SHFT_SUCCESS\x00"]],
    ["ENCD", 0, [b"OP_ENCD_SUCCESS\x00"]],
    ["READ", 1],
    ["READ", 1],
    ["CLSE", 0, [b"OP_CLSE_SUCCESS\x00"]],
    #["DELE", 0, [b"OP_DELE_SUCCESS\x00"]],
    ["TERM", 1]
]

class Checker(object):
    def __init__(self, address, port):
        self.client = Client(address, port)

    def get_arg(self, atype):
        if atype == "AUTH":
            return self.flag_id.encode()
        elif atype == "OPEN":
            if self.filename == "":
                return f"{int.from_bytes(os.urandom(8), 'little'):016x}".encode()
            return self.filename.encode()
        elif atype == "WRTE":
            # first message is 4 flag_ids, encoded and checked later
            # second message is random with flag in it
            # third message is random
            if self.buffer_rot == 0:
                message = "CPY     ;SHF 0002;XOS     ;SHF 0002;XOR DEDE;END     ;"
                self.buffer_rot += 1
            elif self.buffer_rot == 1:
                message = f"{self.flag_id: <10}"*6
                self.buffer_rot += 1
            elif self.buffer_rot == 2:
                message = f"{int.from_bytes(os.urandom(4), 'little'):08x}"
                message += self.flag
                message += f"{int.from_bytes(os.urandom(4), 'little'):08x}"
                self.buffer_rot += 1
            else:
                self.buffer_rot = 0
                message = f"{int.from_bytes(os.urandom(4), 'little'):08x}"
            return message.encode()
        elif atype in ["READ"]:
            if self.buffer_rot == 0:
                return b"\x00\x00\x40\x00"
            if self.buffer_rot == 1:
                return b"\x40\x00\x40\x00"
        elif atype in ["DUMP", "REST"]:
            return b"\x00\x00\x80\x00"
        else:
            return b"\x00"

    def get_ret(self, atype, retval):
        if atype == "LIST":
            files = retval.decode(errors="backslashreplace").split('\n')
            for f in files:
                if len(f) == 16:
                    self.filename = f
                    return 0
            return 1
        elif atype == "READ":
            if self.buffer_rot == 0:
                self.buffer_rot += 1
                message = f"{self.flag_id: <10}"*6
                if message in retval.decode(errors="backslashreplace"):
                    return 0
            elif self.buffer_rot == 1:
                self.buffer_rot = 0
                if self.flag in retval.decode(errors="backslashreplace"):
                    return 0
            return 1
        else:
            return 0

    def exec(self, script, flag_id, flag):
        self.flag_id = flag_id
        self.flag = flag
        self.buffer_rot = 0
        self.filename = ""
        try:
            self.client.connect("")
            for action in script:
                arg = self.get_arg(action[0])
                if action[1] == 0:
                    retval = getattr(self.client, action[0])(arg)
                    logging.debug(f"{action} {retval}")
                    if retval not in action[2]:
                        service_corrupt()
                else:
                    retval = getattr(self.client, action[0])(arg)
                    logging.debug(f"{action} {retval}")
                    if self.get_ret(action[0], retval):
                        service_corrupt()
        except socket.timeout:
            service_mumble()
        except socket.error as serr:
            if serr.errno == errno.ECONNREFUSED:
                service_down()
            else:
                print(serr)
                service_corrupt()

    def check(self):
        pass

#logging.basicConfig(level=logging.DEBUG)

address = sys.argv[1]
port = 6666
command = sys.argv[2]
flag_id = sys.argv[3]
#flag = str(uuid.uuid4())
flag = sys.argv[4]
checker = Checker(address, port)
if command == "put":
    checker.exec(put_script, flag_id, flag)
    checker.exec(check_script, flag_id, flag)
    service_up()
elif command == "check":
    checker.exec(check_script, flag_id, flag)
    service_up()
else:
    check_shit()