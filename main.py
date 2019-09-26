from dns import Query, Resolver

msg = Query(names=[("www.google.com", "A")])

with Resolver() as r:
    r.query(msg, "132.206.44.21")
