import bitstring
from bitstring import pack, BitStream
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
    fmt += ",uint:8=0, uint:16, uint:16"
    name_fields = list(map(lambda x: x.encode(), name_fields))
    msg = pack(fmt, *name_fields, qt, qc)
    return msg

def seek_name(msg):
    field_len = msg[:8].int
    msg = msg[8:]
    name = []
    while field_len > 0:
        field_len_b = field_len*8
        name_field = msg[:field_len_b]
        name.append(str(name_field.bytes, encoding='utf-8'))
        msg = msg[field_len_b:]
        if msg.len > 0:
            field_len = msg[:8].int
        else:
            field_len = 0
        msg = msg[8:]

    return name, msg


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
        self._payload = None

    @property
    def payload(self):
        if self._payload is None:
            self._payload = self._encode()
        return self._payload

    def _encode(self):
        _ctl = pack(self.CTL_FMT, 0, self.opcode, self.aa, 0, self.rd, 0, 0)
        print(_ctl.uint)
        _header = pack(self.HDR_FMT, self.id, _ctl.uint, len(self.names), 0, 0, 0)
        _msg = _header

        if self.names:
            _names = [parse_question(*name) for name in self.names]
            _names = sum(_names)
            _msg += _names

        return _msg

class DNSError(Exception):
    def __init__(self, payload, message=""):
        self.payload = payload
        self.message = message

class FormatError(DNSError):
    pass

class ServerError(DNSError):
    pass

class InvalidNameError(DNSError):
    pass

class ServerRefusedError(DNSError):
    pass

class ResponseTruncatedError(DNSError):
    pass


class Response(object):
    CTL_FMT='uint:1, uint:4, uint:1, uint:1,uint:1,\
             uint:1, uint:3, uint:4'
    HDR_FMT='>6H' # 6 shorts..
    MSG_FMT='bytes:12, bytes:n=-1' # header, body..

    def __init__(self, msg: bytes, query: Query):
        self.raw_msg = msg
        self.query = query
        self._decode(msg, query)
    
    def _decode(self, msg, query):
        msg = BitStream(msg)
        header = msg[:96].unpack(self.HDR_FMT)
        id, ctl, _, qc, rc, _ = header
        ctl = BitStream(bin(ctl))
        _, opcode, aa, tc, rd, ra, _, rcode = ctl.unpack(self.CTL_FMT)
        print(qc,rc)
        if rcode == 1:
            raise FormatError(self.raw_msg)
        elif rcode == 2:
            raise ServerError(self.raw_msg)
        elif rcode == 3:
            raise InvalidNameError(self.raw_msg)
        elif rcode == 5:
            raise ServerRefusedError(self.raw_msg)
        
        if tc == 1:
            raise ResponseTruncatedError(self.raw_msg)

        self.ra = ra
        self.aa = aa

        resp = msg[query.payload.len:]
        name = True
        names = []
        for _ in range(rc):
            if resp[:2].uint == 3:
                name_loc = resp[2:16].uint
                print(name_loc)
                name_raw = msg[name_loc*8:]
                name, _ = seek_name(name_raw)
                resp = resp[16:]
            else:
                name, resp = seek_name(resp)
            print(resp)
            
            names.append(name)

        print(names)


        
        
        
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
        msg = query.payload.bytes
        self.conn.sendto(msg, (server, port))
        result = Response(self.conn.recv(512), query) # Upto 512 bytes
        
        return result


