import bitstring
from bitstring import pack
import socket
import re

def check_name(name_fields):
    pattern = re.compile("^\-|[^A-Za-z0-9\-]+|.*\-$")
    for field in name_fields:
        res = pattern.match(field)
        if res:
            raise ValueError("Invalid domain name field {}".format(field))

def parse_question(name, qtype):
    name_fields = name.rstrip("/").split(".")
    if qtype=="A":
        if "www" != name_fields[0]:
            raise ValueError("Invalid argument domain name {} for query type {}".format(name, qtype))
        qt = 1
        qc = 1
    check_name(name_fields)
    fmt = ','.join(["uint:8={}, bytes:{}".format(len(field), len(field)) for field in name_fields])
    fmt += ", uint:16, uint:16"
    name_fields = list(map(lambda x: x.encode(), name_fields))
    msg = pack(fmt, *name_fields, qt, qc)
    return msg

class Query(object):
    CTL_FMT='uint:1, uint:4, uint:1, uint:1,uint:1,\
             uint:1, uint:3=0, uint:4'
    HDR_FMT='>6H' # 6 shorts..
    QUESTION_FMT='>sHH'

    def __init__(self, id=0, opcode=0, aa=0, rd=0, names=[]):
        self.id = id
        self.opcode = opcode
        self.aa = aa
        self.rd = rd
        self.names = names
    
    def encode(self):
        _ctl = pack(self.CTL_FMT, 0, self.opcode, self.aa, 0, self.rd, 0, 0)
        print(_ctl.uint)
        _header = pack(self.HDR_FMT, self.id, _ctl.uint, len(self.names), 0, 0, 0)
        _msg = _header

        if self.names:
            _names = [parse_question(*name) for name in self.names]
            _names = sum(_names)
            _msg += _names
        
        return _msg.bytes


class Resolver(object):
    def __init__(self, port=9999):
        self.port = port
        self.conn = None

    def __enter__(self):
        if self.conn is None:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.conn.bind(("", self.port))
        return self

    def __exit__(self, *args):
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def query(self, query, server, port=53):
        msg = query.encode()
        self.conn.sendto(msg, (server, port))
        result = self.conn.recv(10)
        print(result)
        return result


