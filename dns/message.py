import re

import bitstring
from bitstring import BitStream, pack

from dns.errors import *

QUERY_TYPE_A = 1
QUERY_TYPE_MX = 15
QUERY_TYPE_NS = 2

QUERY_TYPE_CNAME = 5


def check_name(name_fields):
    pattern = re.compile("^\-|[^A-Za-z0-9\-]+|.*\-$")
    for field in name_fields:
        res = pattern.match(field)
        if res:
            raise FormatError(
                "Invalid character(s) {} in domain name {}".format(
                    res[0], ".".join(name_fields)))


def encode_question(name, qtype):
    """
    Encode a question element in the DNS packet.
    Args:
        name(string): Name to query, varies depending on the query type,
        i.e: www.google.com for query type A.
        qtype(int): Query type, choose from QUERY_TYPE_A ... to QUERY_TYPE_NS.
    Returns:
        Bitstream of encoded question.
    Raises:
        FormatError on invalid domain name for given query type.
    """
    name_fields = name.rstrip("/").split(".")
    check_name(name_fields)
    fmt = ','.join([
        "uint:8={}, bytes:{}".format(len(field), len(field))
        for field in name_fields
    ])
    fmt += ",uint:8=0, uint:16, uint:16=1"
    name_fields = list(map(lambda x: x.encode(), name_fields))
    msg = pack(fmt, *name_fields, qtype)
    return msg


def _decode_name(msg, start):
    info = start[:16]
    if info[:2].uint == 3:  # Pointer:
        ptr = info[2:].uint
        label, _ = _decode_name(msg, msg[ptr * 8:])
        next_ptr = start[16:]
        return label, next_ptr
    else:
        if info[:8].uint == 0:
            return "", start[8:]

        label_len = info[:8].uint * 8
        next_label_ptr = start[8 + label_len:]
        label = str(start[8:8 + label_len].bytes, encoding='utf-8')

        next_label, ptr = _decode_name(msg, next_label_ptr)
        return "{}.{}".format(label, next_label), ptr


def decode_name(full_msg, name_start):
    """
    Decode a possible compressed name from a DNS packet.
    Args:
        full_msg(bytes): Full packet that was received.
        name_start(byte/int): Either a pointer starting from 
        the name or an integer to the offset from the begining of full_msg
        where the name begins.
    Returns:
        List of name elements and the pointer to after this name
        record in full_msg
    """

    name, next_name = _decode_name(full_msg, name_start)

    return name, next_name


def seek_response(response_start, full_msg):
    """
    Decode a reponse field in a DNS message
    Args:
        response_start(Bitstream/int): BitStream starting at the response
        or an integer offset from full_msg where the response begins
        full_msg(BitStream): Full packet as a BitStream
    Returns:
        Tuple (name, answer, query_type, ttl, pointer_to_next), where
        answer depends on query_type: for query_type = QUERY_TYPE_A
        answer will be a single 32 bit IP Address, for QUERY_TYPE_MX
        answer will be (preference, exchange), and for QUERY_TYPE_CNAME
        answer will be the alias, for QUERY_TYPE_NS, answer will be
        the name server.
    Raises:
        ResponsePacketError: If the response packet is inconsistent,
    """
    name, resp = decode_name(full_msg, response_start)
    rtype, rclass, ttl, rdlen = resp[:16 * 5].unpack(
        "uint:16, uint:16, uint:32, uint:16")

    if rclass != 1:
        raise ResponsePacketError(
            "Invalid CLASS on response for name {}".format(name))

    rdata = resp[5 * 16:]
    if rtype == QUERY_TYPE_A:
        ip = rdata[:rdlen * 8]
        answer = "{}.{}.{}.{}".format(ip[:8].uint, ip[8:16].uint,
                                      ip[16:24].uint, ip[24:32].uint)
    elif rtype == QUERY_TYPE_MX:
        pref = rdata[:16].uint
        name, _ = decode_name(full_msg, rdata[16:])
        answer = (pref, name)
    elif rtype == QUERY_TYPE_CNAME:
        answer, _ = decode_name(full_msg, rdata)
    elif rtype == QUERY_TYPE_NS:
        answer, _ = decode_name(full_msg, rdata)

    resp = rdata[rdlen * 8:]

    return name, answer, rtype, ttl, resp


class Query(object):
    CTL_FMT = 'uint:1, uint:4, uint:1, uint:1,uint:1,\
             uint:1, uint:3=0, uint:4'

    HDR_FMT = '>6H'  # 6 shorts..
    QUESTION_FMT = '>sHH'

    def __init__(self, id=0, opcode=0, aa=0, rd=1, names=[]):
        """
        Constructs a query
        Args:
            id: id for the query(default: 0).
            opcode: opcode for the query(default: 0).
            rd: Set to 1 if recursion is desired (default: 1).
            names(list): List of tuples (name(String), query_type(int)).
        Raises:
            FormatError: On invalid names.
        """
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
        _header = pack(self.HDR_FMT, self.id, _ctl.uint, len(self.names), 0, 0,
                       0)
        _msg = _header

        if self.names:
            _names = [encode_question(*name) for name in self.names]
            _names = sum(_names)
            _msg += _names

        return _msg


class Response(object):
    HEADER_SIZE = 6 * 16

    CTL_FMT = 'uint:1, uint:4, uint:1, uint:1,uint:1,\
             uint:1, uint:3, uint:4'

    HDR_FMT = '>6H'  # 6 shorts..

    def __init__(self, msg: bytes, query: Query):
        """
        Constructs a response object from the response payload and initial query.
        Args:
            msg(bytes): Response payload, decoded to construct the object.
            query(Query): Query for this response, used to speed up decoding.
        Raises:
            FormatError: If the query was configured in an invalid manner.
            ServerError: If the server is unable to respond to the query, 
                         usually fixed by setting rd=1 in the query.
            InvalidNameError: Invalid domain name, could not be found.
            ServerRefusedError: The server has refused the dns request.
            ResponseTruncatedError: The DNS response was truncated.
            ResponsePacketError: Invalid format of response packet.
        """
        self.raw_msg = msg
        self.query = query

        self.responses = []
        self.additional = []
        self._decode(msg, query)

    def _decode(self, msg, query):
        msg = BitStream(msg)
        header = msg[:self.HEADER_SIZE].unpack(self.HDR_FMT)

        id, ctl, qc, rc, _, ac = header

        ctl = BitStream(bin(ctl))
        _, opcode, aa, tc, rd, ra, _, rcode = ctl.unpack(self.CTL_FMT)

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
        self.rc = rc
        self.ac = ac

        resp = msg[query.payload.len:]
        name = True
        names = []
        for _ in range(rc):
            name, answer, rtype, ttl, resp = seek_response(resp, msg)
            self.responses.append((name, answer, rtype, ttl))

        for _ in range(ac):
            name, answer, rtype, ttl, resp = seek_response(resp, msg)
            self.additional.append((name, answer, rtype, ttl))

    def _pp_response_list(self, response_list):
        msgs = []
        for response in response_list:
            name, answer, rtype, ttl = response
            if rtype == QUERY_TYPE_A:
                msg = "IP\t{:s}".format(answer)
            elif rtype == QUERY_TYPE_MX:
                pref, alias = answer
                msg = "MX\t{:s}\t{:d}".format(alias, pref)
            elif rtype == QUERY_TYPE_NS:
                msg = "NS\t{:s}".format(answer)
            elif rtype == QUERY_TYPE_CNAME:
                msg = "CNAME\t{:s}".format(answer)
            auth_type = "auth" if self.aa else "nonauth"
            msg = "{:s}\t{:d}\t{:s}".format(msg, ttl, auth_type)
            msgs.append(msg)
        return "\n".join(msgs)

    def __str__(self):
        answer_header = "***\tAnswer Section ({:d} records)\t***".format(
            self.rc)
        answer_section = self._pp_response_list(self.responses)
        parts = [answer_header, answer_section]
        if self.ac > 0:
            additional_header = "***Additional Section ({:d} records)***".format(
                self.ac)
            additional_section = self._pp_response_list(self.additional)
            parts.extend([additional_header, additional_section])

        return "\n".join(parts)
