import hashlib
from Crypto.PublicKey import RSA

# The version of the fingerprint algorithm
FINGERPRINT_VERSION = "0".encode()

# The number of hash iterations to compute the fingerprint
N_ITERATIONS = 5200


class SignalFingerprint:
    """ SignalFingerprint implements Signal's fingerprinting algorithm

    This class enables a user to create a human-readable fingerprint, in order to
    authenticate communications in an out-of-band fashion.
    """

    def __init__(self, *, fingerprint_version: bytes, n_iterations: int, own_id: bytes, own_pubkey: bytes, other_id: bytes, other_pubkey: bytes):
        """ Initializes the SignalFingerprint instance

        Args:
            fingerprint_version (bytes): the version of the fingerprint algorithm, byte encoded
            n_iterations (int): the number of iterations to compute each hash
            own_id (bytes): the identity of this device
            own_pubkey (bytes): the public key of this device
            other_id (bytes): the identity of the device with which we are communicating
            other_pubkey (bytes): the public key of the device with which we are communicating
        """
        self.fingerprint_version = fingerprint_version
        self.n_iterations = n_iterations

        self.own_id = own_id
        self.own_pubkey = own_pubkey

        self.other_id = other_id
        self.other_pubkey = other_pubkey

    def single_hash(self, a: bytes, b: bytes = b'') -> bytes:
        """ Computes the SHA-512 hash of a || b

        Args:
            a (bytes): the first input of the hash
            b (bytes): the second input of the hash

        Returns:
            (bytes): the SHA-512 hash of a||b
        """
        h = hashlib.sha512(a)
        h.update(b)
        return h.digest()

    def iterated_hash(self, a: bytes, b: bytes) -> bytes:
        """ Computes the iterated hash starting from inputs a and b

        For example, if self.n_iterations = 2, then this function computes

        H(H(SHA-512(a) || b) || b)

        Where H corresponds to self.single_hash

        Args:
            a (bytes): the first input of the hash
            b (bytes): the second input of the hash

        Returns:
            (bytes): the SHA-512 hash of a||b
        """
        h = self.single_hash(a)
        for _ in range(self.n_iterations):
            h = self.single_hash(h, b)
        return h

    def truncate(self, fingerprint: bytes, len: int = 30) -> bytes:
        """ Truncates the fingerprint to the appropriate length

        This function takes the first `len` bytes of the fingerprint and returns them

        Args:
            fingerprint (bytes): the fingerprint to be truncated
            len (int): the final length of the truncated fingerprint

        Returns:
            (bytes): the truncated fingerprint
        """
        return fingerprint[:len]

    def to_human_readable(self, fingerprint: bytes) -> str:
        """ This function takes a fingerprint and outputs a human-readable version

        To do so, the fingerprint is divided in 5 Byte chunks. Each chunk is interpreted
        as an unsigned integer (in big-endian order) and reduced modulo 100'000. Each number
        should be padded to 5 digits with zeroes at the start.
        Each chunk is then converted to a string and all chunks are concatenated
        together, separated by spaces.

        Args:
            fingerprint (bytes): the fingerprint to convert to human-readable representation

        Returns:
            str: the human-readable representation of the fingerprint
        """
        if len(fingerprint) % 5 != 0:
            raise AttributeError("Length of fingerprint must be multiple of 5")

        s = []
        for i in range(0, len(fingerprint), 5):
            b = fingerprint[i:i+5]
            n = int.from_bytes(b, byteorder="big", signed=False) % 100000
            s.append(f"{n:05}")
        return " ".join(s)

    def get_fingerprint(self) -> str:
        """ This function returns the fingerprint of self.own_pubkey and self.other_pubkey

        The fingerprint is created by obtaining the human-readable fingerprint of self.own_pubkey and
        self.other_pubkey separately. Then, those fingerprints are concatenated together with a space
        in the middle (User A before user B). The result should be 12 5-digit numbers, separated by spaces.

        Returns:
            str: the human-readable representation of the fingerprint for both users
        """

        fp_a = self.truncate(self.iterated_hash((b"0" + self.fingerprint_version + self.own_pubkey + self.own_id), self.own_pubkey))
        fp_b = self.truncate(self.iterated_hash((b"0" + self.fingerprint_version + self.other_pubkey + self.other_id), self.other_pubkey))
        return " ".join([self.to_human_readable(fp_a), self.to_human_readable(fp_b)])


def main():
    # Ignore the next three lines, they are not relevant for the lab
    own_key = RSA.import_key(bytes.fromhex('3082025c02010002818100e0d98ad355113b51180b70b377d425114e4f4532b0d26c6c286e479453f47a2d67d40bfe4dba925818d6662784601a58f9c85bfd844fd04876febaaa3a08c81102a67dfdf6b40e60755e29df495cf1531712e8915ae8198ff63ba255008c2ee33a71c22f0b2fa96cbff27ec8a0e85394831ead52334f64675b95cd6710c50b0b02030100010281800a478d1ebb440b3e5a5c8f884cebfb23d9922b30e03f9bd5ad5ad9553bd4b0a49470c52443abca16a7fab3f738dde73bcbc8f0025cedaf312e40d80a2c96b68566a05d502c0a99f2ff84e5c20ccb80e4f3047d00124d17b6210db2bdca82bf87b96115ec1a901a8f262157d9b11ad74ef0c7254d47e5e8e35c161021aebff9f1024100ee2ba12bd4cdc4024967c8a51d7bd7e3ac90cbf177774dc2e21c3a5c4823bae82b6f6addfd5df247f3fdfe9606c3e7a7545db31f74196f70a8fd79b43de24b91024100f1aea1b4aacc3ede0a05adc622cdb759eba8f1a451e75c59d28f7054e42a5c8028460e96bf73605e98bba3f3ce4267b3964637d647f1fa27131499453d5906db02402114e0532540db7bf1d43f9367afff01b9c377007836930f81b6a8088f609f22867df85b13494c50e03c24739446fbd34b2da4a6b6ca9da7096203d89c4be5710240774f0f7322121c42fecd98e0c453abdd0f3262c00cd2db4b586009434f33fe6022019bb81da13684dc7f5d4bc19a14999a68e5adb9eca1e2624ffbee2b7fe49b024100a26780878d481d99257575071df59157ee2288ce2036ad25a5af159fd0deda1a24ff21624052ab5e942b76f6b430313bd9c7eb5ee5aa3cbaa5f24114a28b0716'))
    own_pubkey = own_key.public_key().export_key('DER')
    other_pubkey = bytes.fromhex('30819f300d06092a864886f70d010101050003818d0030818902818100b92460d3394aabc2035ad56c24f6bb01735823da9084c235110cca49477145a6d459b8ef3e6aa19f897235160984167a1df7202fb73535e94cc9e6c4711e20735041268abc85caaa57929b09cdcda61be403e66bc93e5bd2f627116e0137e3a25c0a1436d5b87742902fae5f17fdce7019de60427c35c0b0bc1750ea762d82490203010001')

    # Relevant part for the lab below
    fp = SignalFingerprint(
        fingerprint_version=FINGERPRINT_VERSION,
        n_iterations=N_ITERATIONS,
        own_pubkey=own_pubkey,
        own_id=b'Alice',
        other_pubkey=other_pubkey,
        other_id=b'Bob'
    )

    assert(fp.to_human_readable(b'a'*30) == '99585 99585 99585 99585 99585 99585')

    fingerprint = fp.get_fingerprint()
    print(f"If you've done everything correctly, this is your flag: {fingerprint}")

if __name__ == "__main__":
    main()
