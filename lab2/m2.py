#!/usr/bin/env python3
import json
import telnetlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Oracle():
    def ecb_enc(self, prepend_pad:bytes, ciphertext: bytes) -> bytes:
        """ Oracle's encrypt() query.

        Args:
            prepend_pad (bytes): padding to be added
            ciphertext (bytes): AES-ECB encrypted ciphertext with the hidden key of the oracle

        Returns:
            bytes: AES-ECB-Enc(padding + AES-ECB-Dec(ciphertext)) using the hidden oracle key
        """
        pass

class RemoteOracle(Oracle):
    """ This oracle connects to the challenge server.
    The server will run the same code you see in the local oracle.
    Do not change this code.
    """
    RPC_CODE_OK = 0
    def __init__(self, url="localhost", port=50202):
        self.tn = telnetlib.Telnet(url, port)  
        self.num_calls = 0

    def io_call(self, msg:str):
        self.tn.write((msg+"\n").encode("utf-8"))
        response = self.tn.read_until(b"\n")
        if self.num_calls % 100 == 0:
            print("Number of oracle calls:", self.num_calls)
        self.num_calls += 1
        return response.decode("utf-8")

    def close(self):
        self.tn.close()

    def rpc_call(self, msg):
        response = self.io_call(json.dumps(msg))
        obj = json.loads(response)
        if obj["code"] == self.RPC_CODE_OK:
            return obj["result"]
        raise Exception(obj["error"])

    def ecb_enc(self, prepend_pad: bytes, ciphertext: bytes) -> bytes:
        msg = {
            "command": "padded_enc",
            "args": [prepend_pad.hex(), ciphertext.hex()],
            "kwargs": {}
        }
        return bytes.fromhex(self.rpc_call(msg))

class LocalOracle(Oracle):
    """ This oracle instantiates a local AES cipher.
    This allows you to test your attack code.
    Do not change this code.
    """
    def __init__(self, key_size=16, key=None) -> None:
        if key is None:
            self.key = get_random_bytes(key_size)
        else:
            self.key = key

    def ecb_enc(self, prepend_pad: bytes, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, cipher.block_size)
        padded_plaintext = pad(prepend_pad + plaintext, cipher.block_size)
        return cipher.encrypt(padded_plaintext)


def attack(oracle: Oracle, ciphertext: bytes, block_length: int = 16):
    """ ***Your attack code goes here.***

    Args:
        oracle (Oracle): an AES-128-ECB encryption oracle
        ciphertext (bytes): AES-ECB encrypted ciphertext with the hidden key of the oracle
    """
    padding = pad(b'', block_length)
    result = oracle.ecb_enc(padding, ciphertext)
    result = result[:16]
    print(result.hex())

def main():
    block_length = 16
    challenge_ciphertext = ("fbe9b1dfff9eb7b6c4f1ac0cf47e87f66a3b7fe722cdb95"
                            "f96dc65a777634c66759a284ed3fc988858acab21197fb1"
                            "73c80da28c45dfdc082f23afa513cb1af8")

    # Use the local oracle if you want to quickly test your code.
    # Note that it will not yield the correct flag.
    remote = True

    # Do not change the code below.
    if remote:
        oracle = RemoteOracle(url="aclabs.ethz.ch", port=50202)
        ctxt = bytes.fromhex(challenge_ciphertext)
    else:
        oracle = LocalOracle()
        cipher = AES.new(oracle.key, AES.MODE_ECB)
        ctxt = cipher.encrypt(pad("This is a test plaintext for this challenge".encode("utf-8"), cipher.block_size))

    try:
        attack(oracle, ctxt, block_length)
    finally:
        if remote:
            oracle.close()

if __name__ == "__main__":
    main()
