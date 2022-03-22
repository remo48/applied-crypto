from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50303)


def send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
    line = tn.read_until(b'\n')
    return json.loads(line.decode())

def main():
    intro_ciphertext = bytes.fromhex('9e3aee035b47792da0bdbe664341766a8f9a949e0512b88b6872c8d3f649997d')
    intro_padded = pad(b'intro', 16)
    flag_padded = pad(b'flag', 16)
    iv = intro_ciphertext[:16]
    iv_attack = bytes([x^y^z for x,y,z in zip(iv, intro_padded, flag_padded)])
    request = {
        'command': (iv_attack + intro_ciphertext[16:]).hex()
    }
    print(send(request))

if __name__ == '__main__':
    main()
