from telnetlib import Telnet
import json
from Crypto.Random import get_random_bytes


def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def send_guess(tn: Telnet, guess: bool):
    """Sends a guess to the oracle

    Args:
        guess (bool): the guess if the ciphertext was padded correctly

    Returns:
        str: the response of the server 
    """
    json_send(tn, {"guess": guess})
    return json_recv(tn)["res"]


def is_padding_correct(tn: Telnet, ciphertext: bytes):
    """Checks if the plaintext corresponding to the ciphertext is padded correctly. 
    This is done by querying a padding oracle. 
    
    We can use the length of the response to learn something about the encrypted message. 
    The ciphertext corresponding to the encryption of a padding error is always less than 
    or equal to 96 bytes (encryption + iv). Otherwise if the padding is correct, three different
    cases can occur:
      1. UnicodeDecodeError
      2. "Command not recognized" error
      3. The ciphertext is decrypted to the command "hello" and thus a fixed message is returned
    In each of these cases, the length of the encrypted response is greater than 96 bytes. Thus 
    the length of the response of the oracle gives us a hint on the correctness of the padding.

    Args:
        ciphertext (bytes): a byte encoded command

    Returns:
        bool: true if the command is padded correctly
    """
    json_send(tn, {"command": ciphertext.hex()})
    res = json_recv(tn)["res"]
    print(res)
    if len(res) > 96*2:
        return True
    return False


def attack(tn: Telnet):

    for _ in range(3000):
        ciphertext = get_random_bytes(32) 
        # This does not ensure, that all ciphertext blocks are different in all 3000 rounds. 
        # But the probability of a collision is negligible.
        print(ciphertext.hex())
        guess = not is_padding_correct(tn, ciphertext)
        print("Guess:", guess)
        ok = send_guess(tn, guess)
        print(ok)
        if "lost" in ok:
            break
    print(json_recv(tn))


def main():
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50401

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
