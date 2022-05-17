import json
from typing import Tuple
from telnetlib import Telnet

from Crypto.PublicKey.ElGamal import ElGamalKey
from Crypto.PublicKey import ElGamal
from Crypto.Math.Numbers import Integer
from public import ElGamalInterface

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

class ElGamalImpl(ElGamalInterface):
    @classmethod
    def encrypt(cls, key: ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """ Encryption of a message under a given ElGamal public key.
            1. Choose a number k uniformly between 0 and p - 1
            2. Compute the key K = y^k mod p
            3. Compute c1 = g^k mod p
            4. Compute c2 = K*(msg) mod p

        Args:
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """
        k = Integer.random_range(min_inclusive=0, max_exclusive=key.p-1)
        c1 = pow(key.g, k, key.p)
        c2 = (pow(key.y, k, key.p)*Integer.from_bytes(msg)) % key.p
        return c1.to_bytes(), c2.to_bytes()


    @classmethod
    def decrypt(cls, key: ElGamalKey, c1: bytes, c2: bytes) -> bytes:
        """ Decryption of ciphertext under a given key.
            1. Recover the key K = c1^x mod p
            2. Divide c2 by K

        Args:
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """
        c1 = Integer.from_bytes(c1)
        c2 = Integer.from_bytes(c2)
        k = pow(c1, key.x, key.p)
        m = c2*k.inverse(key.p) % key.p
        return m.to_bytes()

class CarpetRemote():
    def __init__(self, tn, carpet_key):
        """ Your initialization code (if any) goes here.
        """
        self.tn = tn
        self.carpet_key = carpet_key
        # Client ElGamalKey (hardcoded since performance of generation is slow)
        p = 127916914252040157945271441669799953689097349976605240543182246135935209190281199523049374975145288226892469182496521677154391032344488631121175721819081904231123965682005717244448046140251022326693245972615997091068251730351949058594405576406857989277782704198237391097206239420077069896595930630081454579007
        g = 86514005018777413859294142807203065946423386657959574201946572730153641558386494008342367207116963899249661150554750845935290208401914403909826732607754282291951867930835538887069905799366723475792877049419226907366497114748318845521418565131349900996775412120220359657132149907092570379410126784482729890337
        y = 81343901564795771274758210377138885463999727024993756130193761892964627010647359853725755081619346884741041622794388531986275539124920834118813124903454010268850650195977890703900739990554324170385206650442339760494446060003174759818913826448447190937541948738654536465455930664419026149361283751004896805086
        x = 22336221568700570981841305053278839852635462623859058718471091224796050953373056768212019461171810030398403283664310883191404380497788339962311076827378586082996521158712142181493262277071141112541410742018564378700837559547799679052930534660361822040580121427945127573676574853922466023673412311503732362572
        self.key: ElGamalKey = ElGamal.construct((p, g, y, x))

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def enc_json_recv(self):
        enc_res = self.json_recv()["enc_res"]
        res = ElGamalImpl.decrypt(self.key,
                bytes.fromhex(enc_res["c1"]),
                bytes.fromhex(enc_res["c2"]))
        return json.loads(res.decode())

    def enc_json_send(self, req: dict):
        request = json.dumps(req)
        c1, c2 = ElGamalImpl.encrypt(self.carpet_key, request.encode())

        obj = {
            "c1": c1.hex(),
            "c2": c2.hex(),
            "p": int(self.key.p),
            "g": int(self.key.g),
            "y": int(self.key.y)
        }
        self.json_send(obj)

    def get_status(self):
        obj = {
            "command": "get_status"
        }
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res

    def get_flag(self):
        obj = {
            "command": "backdoor"
        }
        self.enc_json_send(obj)
        res = self.enc_json_recv()
        return res

def interact(tn: Telnet, carpet_key: ElGamalKey):
    """ Execute the command backdoor on the server
    """

    cr = CarpetRemote(tn, carpet_key)

    print(cr.get_flag())

if __name__ == "__main__":
    PORT = 51010

    from public import carpet_key, carpet_test_key

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_key
    else:
        HOSTNAME = "localhost"
        key = carpet_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key)
