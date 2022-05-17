from telnetlib import Telnet
import json
from passlib.hash import argon2


def recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return line.decode("utf-8")


def send(tn: Telnet, req: str):
    request = req.encode("utf-8")
    tn.write(request + b"\n")


def attack(tn: Telnet):
    pw = bytes.fromhex(recv(tn))
    h = argon2.hash(pw)
    send(tn, h)
    print(recv(tn))


def main():
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50502

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
