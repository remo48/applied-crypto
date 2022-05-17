from itertools import product
from Crypto.Hash import HMAC, SHA1
import hmac
from tqdm import tqdm

HASH = "d262db83f67a37ff672cf5e1d0dfabc696e805bc"
SALT = "b49d3002f2a089b371c3"

def attack(hash, salt):
    lowercase_alphabet = [chr(i) for i in range(97, 123)] # 97 - 123

    for pl in tqdm(product(lowercase_alphabet, repeat = 5), total=26**5):
        p = "".join(pl).encode("utf8")
        digest = hmac.digest(p, salt, "sha1")
        if digest == hash:
            print(p)
            break

if __name__ == "__main__": 
    hash = bytes.fromhex(HASH)
    salt = bytes.fromhex(SALT)
    attack(hash, salt)