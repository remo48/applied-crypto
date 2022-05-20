import json
from math import ceil, prod
from telnetlib import Telnet

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import ceil_div, isPrime

from random import randint, choice

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

def generate_weak_group(n: int):
    """ Generates a prime p with the property, that the discrete logarithm is easy to solve in the
    multiplicative group Zp*.
    """
    def get_smooth_number():
        primes = [10007,
 10009,  10037,  10039,  10061,  10067,  10069,  10079]
        factors = {2 :1}
        x = 2
        while x < n:
            p = choice(primes)
            e = randint(1,5)
            x *= p**e
            factors[p] = factors.get(p, 0) + e
        return factors, x
    
    while True:
        factors, order = get_smooth_number()
        if isPrime(order + 1):
            break
    n = order + 1
    return factors, n

def simultaneous_congruence(modulis, remainder):
    s = 0
    m_prod = prod(modulis)
    for m, r in zip(modulis, remainder):
        p = m_prod // m
        s += r * pow(p, -1, m) * p
    return s % m_prod

def baby_step_giant_step(n, g, h, modulus):
    m = ceil(n**0.5)
    g_map = {}
    for j in range(m):
        g_map[pow(g, j, modulus)] = j
    g_inverse = pow(g**m, -1, modulus)
    y = h
    for i in range(m):
        if y in g_map:
            return (i*m + g_map[y]) % modulus
        y = (y*g_inverse) % modulus

def prime_power_pohlig_hellman(g, p, e, h, modulus):
    x = 0
    y = pow(g, p**(e-1), modulus)
    for i in range(e):
        gx = pow(pow(g, x, modulus), -1, modulus)
        h_k = pow(gx * h, p**(e-1-i), modulus)
        d_k = baby_step_giant_step(p, y, h_k, modulus)
        x = x + p**i * d_k
    return x

def pohlig_hellman(g: int, h: int, n: int, modulus: int, factors):
    modulis = []
    remainder = []
    for p,e in factors.items():
        g_i = pow(g, n // p**e, modulus)
        h_i = pow(h, n // p**e, modulus)
        x_i = prime_power_pohlig_hellman(g_i, p, e, h_i, modulus)
        modulis.append(p**e)
        remainder.append(x_i)
    return simultaneous_congruence(modulis, remainder)

def encode(m: bytes, emLen: int) -> bytes:
    """ Custom EMSA-PKCS1-v1_5-style encoding.
    Follow the rfc8017 section 9.2, with the following exceptions:
    - always use SHA256 as the Hash,
    - discard step 2:
      - let T be (0x) 63 61 72 70 65 74 || H,
      - and tLen be the length in bytes of T.

    If you want to test your implementation against pycryptodome's pkcs1 v1.5 signatures,
    temporarily let T be (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
    Note: that "octet" = byte, "octet string" = bytes object

    Args:
        M (bytes): message to be encoded
        emLen (int): intended length in bytes of the encoded message, as per rfc8017

    Returns:
        EM: encoded message, a bytes object of length emLen
    """
    h = SHA256.new(m)
    t = b"\x63\x61\x72\x70\x65\x74" + h.digest()
    tLen = len(t)
    if emLen < tLen + 11:
        raise AttributeError("intended encoded message length too short")

    ps = (emLen - tLen - 3) * b"\xff"
    em = b"\x00\x01" + ps + b"\x00" + t
    return em

def sign(K: RSA.RsaKey, M: bytes) -> bytes:
    """ Custom RSASSA-PKCS1-v1_5 (RSA Signature Scheme with Appendix)-style signature generation.
    Follow the rfc8017 section 8.2.1, with the following exception:
    - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.

    Args:
        K (RSA.RsaKey): signer's RSA private key.
        M (bytes): message to be signed.

    Returns:
        (bytes): encoded message, a bytes object of length emLen.
    """
    k = ceil_div(K.size_in_bits(), 8)
    em = encode(M, k)
    # 1. OS2IP
    m = int.from_bytes(em, "big")
    # 2. RSASP1
    if not 0 < m < K.n-1:
        raise AttributeError("message representative out of range")
    s = pow(m, K.d, K.n)
    # 3. I2OSP
    signature = s.to_bytes(k, "big")
    return signature

# See M4.0 for this.
def verify(N: int, e: int, M: bytes, S: bytes) -> bool:
    """ Custom RSASSA-PKCS1-v1_5 (RSA Signature Scheme with Appendix)-style signature verification.
    Follow the rfc8017 section 8.2.2, with the following exception:
    - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.

    Args:
        N, e: signer's RSA public key
        M (bytes): message whose signature is to be verified.
        S (bytes): signature to be verified, an bytes object of length k,
                   where k is the length in bytes of the RSA modulus n.

    Returns:
        (bool): True iif the signature is valid.
    """
    k = ceil_div(N.bit_length(), 8)
    # 1. OS2IP
    s = int.from_bytes(S, "big")
    # 2. RSAVP1
    if not 0 < s < N-1:
        return False
    m = pow(s, e, N)
    # 3. I2OSP
    em_1 = m.to_bytes(k, "big")
    # 4. EMSA-PKCS1-v1_5 encode M
    em_2 = encode(M, k)
    return em_1 == em_2

class CarpetRemote():
    def __init__(self, tn: Telnet, carpet_key: RSA.RsaKey, cloud_key: RSA.RsaKey):
        self.tn = tn
        self.carpet_key = carpet_key
        self.cloud_key = cloud_key

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def json_signed_send(self, req: dict, d: int, n: int):
        k = ceil_div(n.bit_length(), 8)
        req_enc = int.from_bytes(encode(json.dumps(req).encode(), k), "big")
        s = pow(req_enc, d, n)
        signature = s.to_bytes(k, "big")
        self.json_send({
            "identity": "carpet",
            "msg": req,
            "signature": signature.hex()
        })

    def save_config(self):
        obj = {
            "msg": {
                "command": "save_config",
            },
            "identity": "carpet_cloud",
            "signature": "00"
        }
        self.json_send(obj)
        res = self.json_recv()
        signed_res = res["signed_res"]

        pub_cfg, priv_cfg = signed_res["pub_cfg"], signed_res["priv_cfg"]

        return (
            (pub_cfg["n"], pub_cfg["e"]),
            (bytes.fromhex(priv_cfg["nonce"]),
                bytes.fromhex(priv_cfg["ciphertext"]),
                bytes.fromhex(priv_cfg["tag"])))

    def restore_config(self, pub_cfg, priv_cfg):
        n, e = pub_cfg
        nonce, ciphertext, tag = priv_cfg

        obj = {
            "msg": {
                "command": "restore_config",
                "pub_cfg": {
                    "n": n,
                    "e": e
                },
                "priv_cfg": {
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex(),
                    "tag": tag.hex()
                },
            },
            "identity": "carpet_cloud",
            "signature": "00"
        }

        self.json_send(obj)
        res = self.json_recv()

        return (res["signed_res"],
            bytes.fromhex(res["signature"]))

    def factory_config(self):
        obj = {
            "msg": {
                "command": "factory_config",
            },
            "identity": "carpet_cloud",
            "signature": "00"
        }

        self.json_send(obj)
        res = self.json_recv()

        return (res["signed_res"],
            bytes.fromhex(res["signature"]))

def attack(tn: Telnet, carpet_key: RSA.RsaKey, carpet_cloud_key: RSA.RsaKey):
    """ Your attack code goes here.
    """
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)

    (n, e), priv_cfg = cr.save_config()
    factors, n_weak = generate_weak_group(n)
    pub_cfg = n_weak, e
    res, signature = cr.restore_config(pub_cfg, priv_cfg)

    s = int.from_bytes(signature, "big")
    m = int.from_bytes(encode(json.dumps(res).encode(), ceil_div(n_weak.bit_length(), 8)), "big")
    d_carpet = pohlig_hellman(m, s, n_weak-1, n_weak, factors)

    cr.factory_config()
    cr.json_signed_send({"command": "backdoor"}, d_carpet, n)

    print(cr.json_recv()["signed_res"]["res"])


if __name__ == "__main__":
    from public import carpet_pubkey, cloud_pubkey
    from public import carpet_test_key, cloud_test_key

    PORT = 51041

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_pubkey
        cloud_key = cloud_pubkey

    else:
        HOSTNAME = "localhost"
        key = carpet_test_key
        cloud_key = cloud_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn, key, cloud_key)
