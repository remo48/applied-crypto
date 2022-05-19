import json
from telnetlib import Telnet

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.number import bytes_to_long, long_to_bytes, ceil_div

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

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
    m = bytes_to_long(em)
    # 2. RSASP1
    if not 0 < m < K.n-1:
        raise AttributeError("message representative out of range")
    s = pow(m, K.d, K.n)
    # 3. I2OSP
    signature = long_to_bytes(s, k)
    return signature

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
    s = bytes_to_long(S)
    # 2. RSAVP1
    if not 0 < s < N-1:
        return False
    m = pow(s, e, N)
    # 3. I2OSP
    em_1 = long_to_bytes(m, k)
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

    def json_signed_send(self, req: dict):
        signature = sign(self.cloud_key, json.dumps(req).encode())
        self.json_send({
            "identity": "carpet_cloud",
            "msg": req,
            "signature": signature.hex()
        })

    def json_signed_recv(self):
        res = self.json_recv()
        signature = bytes.fromhex(res["signature"])

        if "signed_res" in res:
            signed = json.dumps(res["signed_res"]).encode()
        else:
            signed = res["signed_error"].encode()

        if verify(self.carpet_key.n, self.carpet_key.e, signed, signature):
            return signed


    def get_status(self):
        obj = {
            "command": "get_status"
        }
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res

    def get_flag(self):
        obj = {"command": "backdoor"}
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res

def interact(tn: Telnet, carpet_key: RSA.RsaKey, carpet_cloud_key: RSA.RsaKey):
    """ Get the flag here.
    """
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)

    print(cr.get_status())
    print(cr.get_flag())

if __name__ == "__main__":
    from public import carpet_pubkey, cloud_key
    from public import carpet_test_key, cloud_test_key

    PORT = 51040

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_pubkey
        cloud_key = cloud_key

    else:
        HOSTNAME = "localhost"
        key = carpet_test_key
        cloud_key = cloud_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key, cloud_key)
