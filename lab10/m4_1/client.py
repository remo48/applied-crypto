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
    """ Generates a prime p and its factorization with the property, that the discrete logarithm 
    is easy to solve in the multiplicative group Zp*.

    Args: 
        n (int): lower bound for the prime to generate

    Returns:
        tuple(int, int), int: the factors of p-1 and the prime p
    """

    def get_smooth_number():
        """ Compute a smooth number, i.e. a number with only small prime factors.

        Selects a small group of relatively small primes and randomly select their exponent until
        the resulting product has the requested properties.
        
        """
        # s
        primes = [1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223]
        factors = {2 :1} # include 2 to make sure the resulting value is even
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
    """ Solve the system of congruences.
    i.e. x = 3 mod 4
         x = 1 mod 3

    Args:
        modulis (list(int)): the modulis of the system
        remainder (list(int)): the remainder of the systems
    
    """
    s = 0
    m_prod = prod(modulis)
    for m, r in zip(modulis, remainder):
        p = m_prod // m
        s += r * pow(p, -1, m) * p
    return s % m_prod

def baby_step_giant_step(order: int, g: int, h: int, modulus: int):
    """ The Baby-step giant-step algorithm used as a subroutine in the pohlig-hellman algorithm
    to compute the discrete logarithm of an element in a finite abelian group

    Args: 
        g (int): the generator of the group
        order (int): order of the group
        h (int): an element in the group generated by g
        modulus (int): modulus to use for modular arithmetic

    Returns:
        int: the discrete log in for g^x = h mod modulus 

    """
    m = ceil(order**0.5)
    g_map = {}
    for j in range(m):
        g_map[pow(g, j, modulus)] = j
    g_inverse = pow(g**m, -1, modulus)
    y = h
    for i in range(m):
        if y in g_map:
            return (i*m + g_map[y]) % modulus
        y = (y*g_inverse) % modulus

def prime_power_pohlig_hellman(g: int, p: int, e: int, h: int, m: int):
    """ Used as a subroutine in the pohlig-hellman algorithm to compute the discrete log for
    subgroups of prime power order

    Args: 
        g (int): the generator of the group
        p (int): prime factor of subgroup
        e (int): exponent of prime factor of subgroup
        h (int): an element in the group generated by g
        m (int): modulus to use for modular arithmetic

    Returns:
        int: the discrete log in the prime power subgroup <g> 
    """
    x = 0
    y = pow(g, p**(e-1), m)
    for i in range(e):
        gx = pow(pow(g, x, m), -1, m) # g^-x mod m
        h_k = pow(gx * h, p**(e-1-i), m)
        d_k = baby_step_giant_step(p, y, h_k, m)
        x = x + p**i * d_k
    return x

def pohlig_hellman(g: int, h: int, order: int, m: int, factors):
    """ Computes the discrete logarithm for h = g^x mod m with the pohlig-hellman algorithm
    in a group with smooth order with known factors

    Args:
        g (int): the generator of the group
        h (int): an element of the group
        order (int): the order of the group
        m (int): modulus to use for modular arithmetic
        factors (dict(int, int)): a dictionary with the prime factors and their exponent of the order

    Returns:
        int: the discrete logarithm
    """
    modulis = []
    remainder = []
    for p,e in factors.items():
        g_i = pow(g, order // p**e, m)
        h_i = pow(h, order // p**e, m)
        x_i = prime_power_pohlig_hellman(g_i, p, e, h_i, m)
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
    """ The attack to get the flag
    """
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)

    # 1. Save config
    (n, e), priv_cfg = cr.save_config()

    # 2. Generate a modulus n_weak with approx. the same size as n but the underlying group Zn_weak* is 
    #    easy to compute the discrete logarithm
    factors, n_weak = generate_weak_group(n)
    pub_cfg = n_weak, e

    # 3. Restore the config but with the malicious modulus n_weak. The resulting signature s has the property
    #    s = m^d mod n_weak, thus we can extract d by computing the discrete log
    res, signature = cr.restore_config(pub_cfg, priv_cfg)

    # 4. Compute the discrete log to extract the private key of the carpet
    s = int.from_bytes(signature, "big")
    m = int.from_bytes(encode(json.dumps(res).encode(), ceil_div(n_weak.bit_length(), 8)), "big")
    d_carpet = pohlig_hellman(m, s, n_weak-1, n_weak, factors)

    # 5. Restore config and sign the command with the carpets private key
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
