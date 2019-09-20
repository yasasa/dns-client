from dns import Query, Resolver

msg = Query(names=[("www.google.com", "A")])
print(msg.encode())

with Resolver() as r:
    print(r.query(msg, "132.206.44.21"))
