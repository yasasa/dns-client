import time
import socket

from dns.message import Query, Response


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

    def attempt_query(self, query, server, timeout=1., port=53):
        """
        Attempt a single query and return.
        Args:
            query(Query): Query to send.
            server(string): Server address.
            port(int): Server port number (default:53).
            timeout(float): Maximum time in seconds to wait for a 
                            response(default: 1).

        Returns:
            dns.Response containing the response and the query.

        Raises:
            FormatError: If the query was incorrectly configured.
            ServerError: If the server is unable to respond to the query, 
                         usually fixed by setting rd=1 in the query.
            InvalidNameError: Invalid domain name, could not be found.
            ServerRefusedError: The server has refused the dns request.
            ResponseTruncatedError: The DNS response was truncated.
            ResponsePacketError: Invalid format of response packet.
            socket.timeout: Response timed out.
        """

        msg = query.payload.bytes
        self.conn.sendto(msg, (server, port))
        self.conn.settimeout(timeout)
        received_msg = self.conn.recv(512)
        result = Response(received_msg, query)
        return result

    def query(self, query, server, timeout=1., port=53, max_retries=5):
        """
        Attempt a series of queries.
        Args:
            query(Query): Query to send.
            server(string): Server address.
            port(int): Server port number (default:53).
            timeout(float): Maximum time in seconds to wait for a 
                            response.(default: 1).
            max_retries(int): Maximum number of attempts(default: 5).

        Returns:
            dns.Response containing the response and the query.

        Raises:
            FormatError: If the query was incorrectly configured.
            ServerError: If the server is unable to respond to the query, 
                         usually fixed by setting rd=1 in the query.
            InvalidNameError: Invalid domain name, could not be found.
            ServerRefusedError: The server has refused the dns request.
            ResponseTruncatedError: The DNS response was truncated.
            ResponsePacketError: Invalid format of response packet.
            socket.timeout: Timeout on all attempts
        """
        resp = None
        msg = query.payload
        retries = 0
        start = time.time()
        while retries < max_retries and resp is None:
            try:
                resp = self.attempt_query(
                    query, server, timeout=timeout, port=port)
                end = time.time()

            except socket.timeout:
                retries += 1

        if max_retries == retries:
            raise socket.timeout


        return resp, retries, end - start
