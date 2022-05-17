import json
from typing import Optional
from telnetlib import Telnet

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import DSS

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

class CarpetRemote():
    def __init__(self, tn: Telnet, carpet_key: EccKey, cloud_key: EccKey):
        self.tn = tn
        self.carpet_key = carpet_key
        self.cloud_key = cloud_key
        self.identity = "carpet_cloud"

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def json_signed_send(self, req: dict):
        req_hash = SHA256.new(json.dumps(req).encode())
        # Your code here.
        signature = ...
        self.json_send({
            "identity": self.identity,
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

        h = SHA256.new(signed)
        # Your code here.
        verifier = ...
        verifier.verify ...

        return signed

    def get_status(self):
        obj = {
            "command": "get_status"
        }
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res

def interact(tn: Telnet, carpet_key: EccKey, carpet_cloud_key: Optional[EccKey]):
    """ Get the flag here.
    """
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)

    print(cr.get_status())

if __name__ == "__main__":
    from public import carpet_pubkey, cloud_key
    from public import carpet_test_key, cloud_test_key

    PORT = 51030

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
