import demjson


a = "{'jsonrpc': '2.0', 'id': '0', 'result': {'address': '44UZVwSGX6mTeKnSBsFT1ZFRjCTjX1EE1DBmBZj9DtTXZEBYXm6xkRJ7r8uD4dWkVeLe5KutxVjZCFxABP1rEAeSJzHutte'}}"

d = demjson.decode(a)
print(d)
print(d['result']['address'])
#results = d['results']
#print(results)
