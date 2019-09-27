import socket
import argparse

import dns
from dns import Query, Resolver

msg = Query(names=[("gmail.com", dns.QUERY_TYPE_MX)])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS client for MX/NS/A queries.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=5.,
        help=
        "gives how long to wait, in seconds, before retransmitting an unanswered query"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help=
        "maximum number of times to retransmit an unanswered query before giving up"
    )
    parser.add_argument("--port", type=int, default=53, help="UDP port number")
    parser.add_argument(
        "@server",
        type=str,
        help="IPv4 address for DNS server.")
    parser.add_argument(
        "name", type=str, help="Domain name to query for.")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-mx", action="store_true")
    group.add_argument("-ns", action="store_true")

    args = parser.parse_args()
    server = vars(args)['@server'].lstrip("@")
    query_type = dns.QUERY_TYPE_NS if args.ns else dns.QUERY_TYPE_MX if args.mx else dns.QUERY_TYPE_A

    with Resolver() as resolver:
        print("DNS client sending request for {}".format(args.name))
        print("Server: {}".format(server))
        print("Request Type: {}".format("NS" if args.ns else "MX" if args.mx else "A"))
        query = Query(names=[(args.name, query_type)])
        try:
            response, attempts, time = resolver.query(query, server, timeout=args.timeout, port=args.port, max_retries=args.max_retries)
            print("Response received after {:.2f} seconds ({} retries)".format(time, attempts))
            print(response)
        except dns.InvalidNameError:
            print("NOTFOUND")
        except socket.timeout as e:
            print("ERROR\tRequest Timed Out:",e)
        except dns.FormatError as e:
            print("ERROR\tIncorrect Input Format:", e)
        except dns.ServerRefusedError:
            print("ERROR\tRequest Refused")
        except dns.ResponseTruncatedError:
            print("ERROR\tResponse Truncated")
        except dns.ResponsePacketError as e:
            print("ERROR\tUnexpected Response:", e)
        except dns.ServerError:
            print("ERRPR\tServer Error")

        
