from telnetlib import Telnet
import json
from Crypto.Random import get_random_bytes


def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def send_guess(tn: Telnet, guess: str):
    """Sends a guess to the oracle

    Args:
        guess (str): the guess of the salt

    Returns:
        str: the response of the server 
    """
    json_send(tn, {"guess": guess})
    return json_recv(tn)["res"]


def is_padding_correct(tn: Telnet, ciphertext: bytes):
    """Checks if the plaintext corresponding to the ciphertext is padded correctly. 
    This is done by querying a padding oracle. See m1 for further details

    Args:
        ciphertext (bytes): a byte encoded command

    Returns:
        bool: true if the command is padded correctly
    """
    json_send(tn, {"command": ciphertext.hex()})
    res = json_recv(tn)["res"]
    if len(res) > 112*2:
        return True
    return False


def get_initial_ciphertext(tn: Telnet):
    """Gets a random ciphertext from the server including the salt

    Args:
        tn (Telnet): a telnet client

    Returns:
        str: ciphertext (iv + encrypted(salt + something))
    """
    json_send(tn, {"command": bytes(32).hex()})
    return json_recv(tn)["res"]


def byte_xor(a: bytes, b: bytes):
    """Performs bytewise xor of two equal length byte arrays

    Args:
        a (bytes): the first byte array
        b (bytes): the second byte array
    """
    return bytearray([x ^ y for x, y in zip(a, b)])


def attack(tn: Telnet):
    """Performs the attack

    The attack works the same way as in exercise m2. We recover the salt starting from the 
    last byte and continously decrypt the previous byte by using the information already known.

    Args:
        tn (Telnet): a telnet client
    """
    # Note as salt is a hex string, only hex characters must be considered
    possible_values = [48, 49, 50, 51, 52, 53,
                       54, 55, 56, 57, 97, 98, 99, 100, 101, 102]
    for _ in range(100):
        ciphertext = bytes.fromhex(get_initial_ciphertext(tn))[:32]
        delta_success = bytearray(16)
        for i in range(1, 17):
            # delta_success contains the last i plaintext bytes.
            delta = byte_xor(delta_success, bytes(16-i+1) + bytes((i-1)*[i]))
            for j in possible_values:
                delta[-i] = j ^ (i)
                if is_padding_correct(tn, byte_xor(ciphertext[:16], delta) + ciphertext[16:]):
                    delta_success[-i] = delta[-i] ^ (i)
                    break
        guess = delta_success.decode()
        print("Guess:", guess)
        ok = send_guess(tn, guess)
        print(ok)
        if "lost" in ok:
            return
    print(json_recv(tn))


def main():
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50403

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
