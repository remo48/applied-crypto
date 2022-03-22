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
        guess (str): the guess of the last byte of the salt

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


def attack(tn: Telnet):
    """Performs the attack

    The last byte of the salt is decrypted by performing a padding oracle attack.
    In our example the ciphertext is equal to c = iv | c1 | c2 | ... whereas c1 is the 
    encryption of the salt. Thus changing the last byte of the iv (xor with delta) results 
    in a change of the last byte of c1. We then set c1 as the last block of the ciphertext 
    and query a padding oracle. If the padding is correct, simple math can be used to get
    the true plaintext byte of the salt: p1[15] = delta ^ 0x01. Note that 0x02 0x02 can not
    occur, since the salt contains only hex characters

    Args:
        tn (Telnet): a telnet client
    """
    # Note as salt is a hex string, only hex characters must be considered
    possible_values = [48, 49, 50, 51, 52, 53,
                       54, 55, 56, 57, 97, 98, 99, 100, 101, 102]
    for _ in range(1000):
        ciphertext = bytes.fromhex(get_initial_ciphertext(tn))[:32]
        delta = bytearray(ciphertext)
        for j in possible_values:
            delta[15] = ciphertext[15] ^ j ^ 1
            if is_padding_correct(tn, delta):
                guess = chr(j)
                print("Guess:", guess)
                ok = send_guess(tn, guess)
                print(ok)
                if "lost" in ok:
                    return
                break
    print(json_recv(tn))


def main():
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50402

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
