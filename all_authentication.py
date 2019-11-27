from flask import Flask, request, render_template, session, jsonify
import base64
import jwt
import time
import random
import re
import hashlib


app = Flask(__name__)
app.config["BASIC_AUTH_USERNAME"] = "ngoclam_athena"
app.config["BASIC_AUTH_PASSWORD"] = "athenaforthewin"
app.secret_key = 'any random string'
data = base64.b64encode("ngoclam_athena:athenaforthewin".encode("utf-8"))
# print(data.decode("utf-8"))

def parse_diggest_header(diggest_header):
    reg = re.compile(r'(\w+)[:=] ?"?([\w\/]+)"?')
    return dict(reg.findall(diggest_header))

def generate_random_value():
    return "%032x"% random.getrandbits(128)

@app.route("/basic_auth", methods=["POST"])
def basic_auth():
    auth_header = request.headers.get("Authorization", None)
    if auth_header == "Basic " + data.decode("utf-8"):
        current_time = time.time()
        value = "%032x"% random.getrandbits(128)
        encoded_data = jwt.encode({"from" : current_time, "to" : current_time + 60, "data" : value}, "secret", algorithm="HS256").decode("utf-8") # THIS OUTPUT IS BYTE
        if "Bearer" not in session:
            session["Bearer"] = []
        session["Bearer"].append(encoded_data)
        return jsonify({"access_token" : encoded_data})
    else :
        return "FAIL"

@app.route("/bearer_auth", methods=["POST"])
def bearer_auth():
    bearer_header = request.headers.get("Authorization", None)
    encoded_data = bearer_header.split("Bearer ")[-1]
    if encoded_data in session["Bearer"]:
        data = jwt.decode(encoded_data, "secret", algorithms=["HS256"])
        if  time.time() < data["to"]:
            return "THIS IS WHAT YOU WANT"
        else:
            return "TOKEN EXPIRED"
    else:
        return "INVALID TOKEN"
    return "FAIL"

@app.route("/diggest_auth", methods=["GET", "POST"])
def diggest_auth():
    if request.method == "GET":
        realm="diggest_auth"
        nonce=generate_random_value()
        algorithm="MD5"
        qop="auth"
        session["server_nonce"] = nonce
        print(generate_random_value())
        return jsonify({"realm" : realm, "nonce" : nonce, "algorithm" : algorithm, "qop" : qop})
    elif request.method == "POST":
        header_dict = parse_diggest_header(request.headers.get("Authorization"))
        print(header_dict)
        md1 = hashlib.md5("{}:{}:{}".format(header_dict["username"], header_dict["realm"], app.config.get("BASIC_AUTH_PASSWORD")).encode("utf-8")).digest()
        md2 = hashlib.md5("{}:{}".format(request.method, header_dict["uri"]).encode("utf-8")).digest()
        result = hashlib.md5("{}:{}:{}:{}:{}".format(md1, header_dict["nonce"], header_dict["nonceCount"], header_dict["cnonce"], md2).encode("utf-8")).hexdigest()
        if result == header_dict["response"]:
            return "THIS IS WHAT YOU WANT"
        return "FAIL"



if __name__ == "__main__":
    app.run(debug=True)