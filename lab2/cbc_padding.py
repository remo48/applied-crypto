from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Oracle():
    def ecb_enc(self, ciphertext: bytes) -> bytes:
        """ Oracle's encrypt() query.

        Args:
            prepend_pad (bytes): padding to be added
            ciphertext (bytes): AES-ECB encrypted ciphertext with the hidden key of the oracle

        Returns:
            bytes: AES-ECB-Enc(padding + AES-ECB-Dec(ciphertext)) using the hidden oracle key
        """
        pass

class PaddingOracle():
    """ This oracle instantiates a local AES cipher.
    This allows you to test your attack code.
    Do not change this code.
    """
    def __init__(self, iv, key_size=16, key=None) -> None:
        self.iv = iv
        if key is None:
            self.key = get_random_bytes(key_size)
        else:
            self.key = key

    def ecb_enc(self, ciphertext: bytes) -> bool:
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        plaintext = cipher.decrypt(ciphertext)
        try:
            plaintext = unpad(plaintext, cipher.block_size)
        except:
            return False
        return True

def byte_xor(ba1, ba2):
    return bytearray([_a ^ _b for _a, _b in zip(ba1, ba2)])

def attack(oracle: Oracle, ciphertext: bytes, iv: bytes, block_length: int = 16):
    """ ***Your attack code goes here.***

    Args:
        oracle (Oracle): an AES-128-ECB encryption oracle
        ciphertext (bytes): AES-ECB encrypted ciphertext with the hidden key of the oracle
    """
    plaintext = bytearray(len(ciphertext))
    ciphertext = iv + ciphertext

    for k in range(32, len(ciphertext) - block_length, block_length):
        delta_success = bytearray(16)
        for i in range(block_length):
            delta = byte_xor(delta_success, bytes(block_length-i) + bytes(i*[i+1]))
            for j in range(0, 256):
                # 1. fill delta array
                delta[-i-1] = j
                # 2. & 3. xor with previous ciphertext block, query padding oracle, if padding is valid then store guess j in delta_success
                if oracle.ecb_enc(byte_xor(ciphertext[k:k+block_length], delta) + ciphertext[k+block_length:k+2*block_length]):
                    # 4. resolve ambuigity where oracle succeedes for 0x02 0x02
                    delta_success[-i-1] = j^(i+1)
                    break
        plaintext[k:k+block_length] = delta_success
    print(plaintext)
        

def main():
    block_length = 16
    iv = get_random_bytes(16)
    oracle = PaddingOracle(iv)
    cipher = AES.new(oracle.key, AES.MODE_CBC, iv=iv)
    ctxt = cipher.encrypt(pad("This is a test plaintext for this challenge".encode("utf-8"), cipher.block_size))
    attack(oracle, ctxt, iv, block_length)


if __name__ == "__main__":
    main()