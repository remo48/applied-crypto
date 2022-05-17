import hashlib

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


def main():
    fp = SignalFingerprint(
        fingerprint_version=FINGERPRINT_VERSION,
        n_iterations=N_ITERATIONS,
        # The following parameters are not relevant since we will not use them for now
        own_pubkey=b'',
        own_id=b'',
        other_pubkey=b'',
        other_id=b''
    )

    fingerprint = fp.truncate(fp.iterated_hash(b'Did you see?', b'He just turned himself into a pickle')).hex()
    print(f"If you've done everything correctly, this is your flag: {fingerprint}")

if __name__ == "__main__":
    main()
