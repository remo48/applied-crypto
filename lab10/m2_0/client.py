import json
from typing import Tuple, Optional
from telnetlib import Telnet

from Crypto.PublicKey.ECC import EccKey, EccPoint
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

from public import ECCInterface

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

"""
This is the client code that you should use for M2.0

Implement the functions `ecc_point_to_bytes`, `derive_symmetric_keys`, `encrypt` and `decrypt` in the class `ECCImpl`.

You may change the `__init__` function of the `CarpetRemote` class to include your initialization code.
"""


class ECCImpl(ECCInterface):
    @staticmethod
    def ecc_point_to_bytes(point: EccPoint):
        """Compute the byte-representation of an elliptic curve point

        To compute a representation, we use the 1363-2000 IEEE Standard (Specifications for Public Key Cryptography). You can find the PDF here (use your ETH credentials):

        https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=891000

        This function should implement the EC2OSP specification. Mind that we are using *uncompressed* points for our purposes.
        """
        pc = b"\x04" # 00000100
        q = point.size_in_bytes()
        return pc + point.x.to_bytes(q) + point.y.to_bytes(q)

    @classmethod
    def derive_symmetric_keys(
        cls, privkey: EccKey, pubkey: EccKey
    ) -> Tuple[bytes, bytes]:
        """Derive an encryption key and a decryption key from a private EccKey and a public EccKey

        This method effectively implements the Elliptic Curve Diffie-Hellman key exchange.
        Given the client's private key and the server's public key, derive a shared point on the elliptic curve.

        Then, to derive one of the keys, compute:
            1. The byte representation of the shared point
            2. The byte representation of the pubkey of the receiver
            3. The byte representation of the pubkey of the sender
        using the `ecc_point_to_bytes` function above.

        Then, concatenate these three byte strings in the same order as above. Finally, hash the result with SHA-256. This will leave you with a 32-Byte AES-GCM key.

        For the encryption key, the sender will be the Client and the receiver will be the Server. For the decryption key, it will be the other way around. This yields two AES-GCM keys in total.

        Args:
            privkey (EccKey): the private key of the client
            pubkey (EccKey): the public key of the server

        Returns:
            (bytes, bytes): respectively, the AES-GCM encryption key and the AES-GCM decryption key
        """
        sp = privkey.d * pubkey.pointQ
        key_enc = SHA256.new(
            cls.ecc_point_to_bytes(sp) + 
            cls.ecc_point_to_bytes(pubkey.pointQ) + 
            cls.ecc_point_to_bytes(privkey.pointQ)).digest()
        key_dec = SHA256.new(
            cls.ecc_point_to_bytes(sp) + 
            cls.ecc_point_to_bytes(privkey.pointQ) + 
            cls.ecc_point_to_bytes(pubkey.pointQ)).digest()
        return key_enc, key_dec

    @classmethod
    def encrypt(
        cls, key_enc: bytes, message: bytes, nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Your encryption code goes here.

        Use AES-GCM to encrypt `message` under `key_enc`. If the nonce is provided, you should use it. Otherwise, generate a random one. You should not include any Additional Data.

        Args:
            key_enc (bytes): The AES-GCM key to use for the encryption
            msg (bytes): the plaintext message to be sent
            nonce (Optional[bytes]): the nonce to be used for AES-GCM, if provided

        Returns:
            ciphertext (bytes): the AES-GCM encrypted ciphertext
            tag (bytes): the AES-GCM MAC tag
            nonce (bytes): the AES-GCM nonce
        """
        aes = AES.new(key_enc, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = aes.encrypt_and_digest(message)
        return ciphertext, tag, aes.nonce

    @classmethod
    def decrypt(
        cls, key_dec: bytes, ciphertext: bytes, tag: bytes, nonce: bytes
    ) -> bytes:
        """Your decryption code goes here.

        Use AES-GCM to decrypt `ciphertext` under `key_enc`, using the given `tag` and `nonce`.

        Args:
            key_dec (bytes): The AES-GCM key to use for the decryption
            ciphertext (bytes): the AES-GCM encrypted ciphertext to be decrypted
            tag (bytes): the AES-GCM tag for the MAC
            nonce (bytes): the AES-GCM nonce

        Returns:
            (bytes): the plaintext message
        """
        aes = AES.new(key_dec, AES.MODE_GCM, nonce=nonce)
        plaintext = aes.decrypt_and_verify(ciphertext, tag)
        return plaintext


class CarpetRemote:
    def __init__(self, tn, carpet_key):
        """Your initialization code (if any) goes here."""
        self.tn = tn
        self.carpet_key = carpet_key

        self.key: EccKey = ECC.generate(curve="NIST P-256")
        symmetric_key = ECCImpl.derive_symmetric_keys(self.key, self.carpet_key)
        self.key_enc: bytes = symmetric_key[0]
        self.key_dec: bytes = symmetric_key[1]

    def set_user_key(self):
        self.json_send(
            {
                "command": "set_user_key",
                "x": hex(self.key.pointQ.x)[2:],
                "y": hex(self.key.pointQ.y)[2:],
            }
        )
        res = self.json_recv()
        return res

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode("utf-8"))

    def json_send(self, req: dict):
        request = json.dumps(req).encode("utf-8")
        self.tn.write(request + b"\n")

    def enc_json_recv(self):
        enc_res = self.json_recv()["enc_res"]
        ciphertext = bytes.fromhex(enc_res["ciphertext"])
        tag = bytes.fromhex(enc_res["tag"])
        nonce = bytes.fromhex(enc_res["nonce"])

        res = ECCImpl.decrypt(self.key_dec, ciphertext, tag, nonce)

        return json.loads(res.decode())

    def enc_json_send(self, req: dict):
        request = json.dumps(req)
        ctxt, tag, nonce = ECCImpl.encrypt(self.key_enc, request.encode())

        obj = {
            "ciphertext": ctxt.hex(),
            "tag": tag.hex(),
            "nonce": nonce.hex(),
        }
        self.json_send(obj)

    def get_status(self):
        obj = {"command": "get_status"}
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res

    def get_flag(self):
        obj = {"command": "backdoor"}
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res

def interact(tn: Telnet, carpet_key: EccKey):
    """Your attack code goes here."""

    cr = CarpetRemote(tn, carpet_key)
    cr.set_user_key()
    print(cr.get_status())
    print(cr.get_flag())


if __name__ == "__main__":
    PORT = 51020

    from public import carpet_pubkey, carpet_test_pubkey

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_pubkey
    else:
        HOSTNAME = "localhost"
        key = carpet_test_pubkey

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key)
