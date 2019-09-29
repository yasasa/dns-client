# DNS Resolver (ECSE 416)

## Overview
This is a simple DNS Resolver packaged in a self contained library. Query types currently supported are: `A | NS | MX` thus far.

## Dependencies
This tool uses Python 3, tested on Python 3.7.4.

To install the dependencies and run the package you can use:

`pip install .`

## Usage:
For usage instructions use:

`python main.py -h`

To use as a library:
```python3
import dns

query = dns.Query(names=[("gmail.com", dns.QUERY_TYPE_MX)])
with dns.Resolver() as resolver:
  response = resolver.query(query, "8.8.8.8", port=53)
  print(response)
```

### Errors
The program will raise various errors based on the server response, more infomration can be found using `help(Resolver.query)`
