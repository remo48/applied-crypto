from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50305)


def send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
    line = tn.read_until(b'\n')
    return json.loads(line.decode())

def padding_oracle(ciphertext: bytes):
    res = send({'command': ciphertext.hex()})
    return res['res'] == 'Failed to execute command: ValueError: No such command.'

def byte_xor(ba1, ba2):
    return bytearray([_a ^ _b for _a, _b in zip(ba1, ba2)])

def main():
    ciphertext = get_random_bytes(16)
    delta_success = bytearray(16)
    for i in range(16):
        delta = byte_xor(delta_success, bytes(16-i) + bytes(i*[i+1]))
        for j in range(0, 256):
            # 1. fill delta array
            delta[-i-1] = j
            # 2. & 3. xor with ciphertext block, query padding oracle, if padding is valid then store guess j in delta_success
            if padding_oracle(byte_xor(ciphertext, delta)):
                # 4. resolve ambuigity where oracle succeedes for 0x02 0x02
                delta_success[-i-1] = j^(i+1)
                break
        print(delta_success)
    
    key = byte_xor(ciphertext, delta_success)
    command = byte_xor(key, pad(b'flag', 16))
    print(send({'command': command.hex()}))

if __name__ == '__main__':
    main()