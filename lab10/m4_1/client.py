import json
from telnetlib import Telnet

from Crypto.PublicKey import RSA

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

# See M4.0 for this.
def sign(K: RSA.RsaKey, M: bytes) -> bytes:
    raise NotImplementedError

# See M4.0 for this.
def verify(N: int, e: int, M: bytes, S: bytes) -> bool:
    raise NotImplementedError

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

    print(cr.save_config())

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
