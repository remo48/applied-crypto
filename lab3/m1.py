from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50301)


class StrangeCTR():
    def __init__(self, key: bytes, nonce: bytes = None, initial_value: int = 0, block_length: int = 16):
        """Initialize the CTR cipher.
        """

        if nonce is None:
            # Pick a random nonce
            nonce = get_random_bytes(block_length//2)

        self.nonce = nonce
        self.initial_value = initial_value
        self.key = key
        self.block_length = block_length

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CTR mode:

        C_i = E_k(N || c(i)) xor P_i xor 1337

        Uses nonce, counter initial value and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext
        """
        ciphertext = AES.new(self.key, AES.MODE_CTR, initial_value=self.initial_value,
                             nonce=self.nonce).encrypt(pad(plaintext, self.block_length))
        l = int(len(ciphertext) / self.block_length)
        xor_mask = (1337).to_bytes(self.block_length, 'big') * l
        ciphertext = bytes([x ^ y for x, y in zip(ciphertext, xor_mask)])
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CTR mode.

        Uses nonce, counter initial value and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """
        l = int(len(ciphertext) / self.block_length)
        xor_mask = (1337).to_bytes(self.block_length, 'big') * l
        ciphertext = bytes([x ^ y for x, y in zip(ciphertext, xor_mask)])
        plaintext = AES.new(
            self.key, AES.MODE_CTR, initial_value=self.initial_value, nonce=self.nonce).decrypt(ciphertext)
        return unpad(plaintext, self.block_length)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def attack():
    ciphertext = bytes.fromhex('01f0ceb3dad5f9cd23293937c893e0ec')
    #xor_mask = (1337).to_bytes(16, 'big')
    #ciphertext = bytes([x ^ y for x, y in zip(ciphertext, xor_mask)])
    plaintext = pad(b'intro', 16)
    key = bytes([x ^ y for x, y in zip(ciphertext, plaintext)])
    encrypted_command = bytes([x ^ y for x, y in zip(key, pad(b'flag', 16))])

    request = {
        "command": encrypted_command.hex()
    }
    json_send(request)

    response = json_recv()
    return response


def main():
    cipher = StrangeCTR(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    print(attack())


if __name__ == "__main__":
    main()
