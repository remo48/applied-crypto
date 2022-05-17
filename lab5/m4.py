from telnetlib import Telnet
import json
from itertools import product
from Crypto.Hash import HMAC, SHA256
import hmac
import hashlib
import random


def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")

def xor(a: bytes, b: bytes):
    return bytes([x^y for x,y in zip(a,b)])

class HMAC256:
    def __init__(self, key: bytes):
        key = key + b'\x00' * (64 - len(key))
        trans_5C = bytes((x ^ 0x5C) for x in range(256))
        trans_36 = bytes((x ^ 0x36) for x in range(256))

        self.h_inner = hashlib.sha256(key.translate(trans_36))
        self.h_outer = hashlib.sha256(key.translate(trans_5C))

    def compute(self, msg: bytes):
        h_inner = self.h_inner.copy()
        h_outer = self.h_outer.copy()
        h_inner.update(msg)
        h_outer.update(h_inner.digest())
        return h_outer.digest()

def break_hash2(h: HMAC256, hash: bytes):
    lowercase = 'abcdefghijklmnopqrstuvwxy'
    for pl in product(lowercase, repeat = 5):
        pw = "".join(pl).encode("utf8")
        digest = h.compute(pw)
        if hash == digest:
            return pw

def break_hash(salt: bytes, hash: bytes):
    lowercase = 'abcdefghijklmnopqrstuvwxy'
    for pl in product(lowercase, repeat = 5):
        pw = "".join(pl).encode("utf8")
        digest = hmac.digest(salt, pw, digest="sha256")
        if hash == digest:
            return pw


def attack(tn: Telnet):
    salt = bytes.fromhex(json_recv(tn)["salt"])
    h = HMAC256(salt)
    json_send(tn, {"command": "password"})
    pw_hash = bytes.fromhex(json_recv(tn)["pw_hash"])
    pw = break_hash2(h, pw_hash)
    json_send(tn, { 'command' : 'guess', 'args' : { 'pw' : pw.decode("utf8") }})
    print(json_recv(tn))


def main():
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50504

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
