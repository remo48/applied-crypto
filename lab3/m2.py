from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50302)

def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def main():
    while(True):
        random_ciphertext = get_random_bytes(16)
        
        request = {
            "command": random_ciphertext.hex()
        }
        json_send(request)
        response = json_recv()
        msg = response['res'].split(': ')
        if msg[2] == 'No such command':
            plaintext = pad(bytes.fromhex(msg[3]), 16)
            key = bytes([x^y for x,y in zip(plaintext, random_ciphertext)])
            encrypted_command = bytes([x ^ y for x, y in zip(key, pad(b'flag', 16))])
            request = {
                "command": encrypted_command.hex()
            }
            json_send(request)
            response = json_recv()
            print(response)
            return


if __name__ == '__main__':
    main()