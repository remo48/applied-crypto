from cmath import sqrt
import json
from math import ceil, prod
from random import choice, randint
from Crypto.Util.number import isPrime, ceil_div
from Crypto.Random import get_random_bytes

from client import encode, generate_weak_group, pohlig_hellman

if __name__ == "__main__":
    factors, n = generate_weak_group(64)
    m = {"res": "ok"}
    m = encode(json.dumps(m).encode(), ceil_div(n.bit_length(),8))
    m = int.from_bytes(m, "big")
    h = pow(m, 12345, n)

    # print(pohlig_hellman(2, 10, 12, 13, {2 :2, 3: 1}))
    print(pohlig_hellman(m, h, n-1, n, factors))

