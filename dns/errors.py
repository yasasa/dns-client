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


class ResponsePacketError(DNSError):
    pass


class ResponseTruncatedError(DNSError):
    pass
