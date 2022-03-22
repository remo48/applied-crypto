from Crypto.Cipher import AES
from Crypto.Hash import SHA256

CIPHERTEXT = "05b4a85063e12931ce340321eb5141b24ee81ed6c10e9eae8991198ac796"\
"f4ff019aa75aabdd24ec2c6145d879c88faefb38563b870b65b87f3ce522"\
"e065fcf93bd0c6b60398724364ed7da5b17a2c042205628330e42e4a9c5b"\
"ccfc3645b54d"
CONST_IV = "e764ea639dc187d058554645ed1714d8"

def aes_cbc_decryption(ciphertext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def generate_aes_key_from_int(integer: int, key_length: int):
    seed = (integer).to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key

def check_meaningful(plaintext: bytes):
    return plaintext.isascii()

def main():
    ciphertext = bytes.fromhex(CIPHERTEXT)
    iv = bytes.fromhex(CONST_IV)

    for i in range(0x10000):
        key = generate_aes_key_from_int(i, 16)
        plaintext = aes_cbc_decryption(ciphertext, key, iv)
        if check_meaningful(plaintext):
            print(plaintext)


if __name__ == '__main__':
    main()