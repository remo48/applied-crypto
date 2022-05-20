from cmath import sqrt
import json
from math import ceil, prod
from random import choice, randint
from Crypto.Util.number import isPrime, ceil_div
from Crypto.Random import get_random_bytes

from client import encode, generate_weak_group, pohlig_hellman
from public import carpet_test_key

def find_order(g: int, modulus):
    for i in range(1, modulus):
        if pow(g, i, modulus) == 1:
            return i

def get_orders(n):
    for i in range(1, n):
        elems = []
        for j in range(1, n):
            e = pow(i, j, n)
            elems.append(e)
            if e == 1:
                break
        print(f"{i}: {len(elems)}")


if __name__ == "__main__":
    for i in range(20):
        factors, n = generate_weak_group(carpet_test_key.n)
        m = {"res": "ok"}
        m = encode(json.dumps(m).encode(), ceil_div(n.bit_length(),8))
        m = int.from_bytes(m, "big")
        h = pow(m, carpet_test_key.d, n)

        # print(pohlig_hellman(8, 4, 11, 23, {11: 1}))
        d_rec = pohlig_hellman(m, h, n-1, n, factors)
        assert(d_rec == carpet_test_key.d)
