import hashlib

server_nonce = "d6f1db8a00716676e034a4236854d1b4"
client_nonce = "fdea9aa0011ccd75ba61387fec435fdf"

data1 = {
    "username" : "ngoclam_athena",
    "realm" : "diggest_auth",
    "password" : "athenaforthewin"
}

data2 = {
    "method" : "POST",
    "uri" : "/diggest"
}

algorithm = "MD5"
qop = "auth"
nonceCount = "1"

md1 = hashlib.md5("{}:{}:{}".format(data1["username"], data1["realm"], data1["password"]).encode("utf-8")).digest()
md2 = hashlib.md5("{}:{}".format(data2["method"], data2["uri"]).encode("utf-8")).digest()

response = hashlib.md5("{}:{}:{}:{}:{}".format(md1, server_nonce, nonceCount, client_nonce, md2).encode("utf-8")).hexdigest()
print(md1)
print(md2)
print(response)

print("username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm=\"{}\", response=\"{}\", qop=\"{}\", nonceCount=\"{}\", cnonce=\"{}\"".format(
                                            data1["username"],
                                            data1["realm"],
                                            server_nonce,
                                            data2["uri"],
                                            algorithm,
                                            response,
                                            qop,
                                            nonceCount,
                                            client_nonce
))