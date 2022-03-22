from telnetlib import Telnet
import json

def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))

def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")

def send_oracle_command(tn: Telnet, m0: str, m1: str) -> str:
    """Sends the challenge messages to the IND-CPA oracle

    Args:
        tn (Telnet): a telnet client
        m0 (str): first message to encrypt
        m1 (str): second message to encrypt

    Returns:
        str: the response of the server
    """
    json_send(tn, {"command": "oracle", "m0": m0, "m1": m1})
    return json_recv(tn)["res"]

def send_guess(tn: Telnet, guess: int) -> str:
    """Sends a guess to the oracle

    Args:
        tn (Telnet): a telnet client
        guess (int): 0/1 the guess of which message the oracle encrypted in the response

    Returns:
        str: the response of the oracle
    """
    json_send(tn, {"command": "guess", "guess": guess})
    return json_recv(tn)["res"]

def attack(tn: Telnet):
    """ Your attack code goes here.

    IND-CPA requires the messages sent to the oracle by the advisor to be of the same length. If this property
    is not met, IND-CPA says nothing about security. This implementation of the LoR Oracle allows for different
    length messages and thus we can abuse this fact to gain an advantage of 1 in the IND-CPA-Game by choosing two
    messages that are encrypted to ciphertexts with different length.
    """
    msg0 = "short message"
    msg1 = "long message, which is more than one block long"
    for _ in range(1000):
        print("Message 1:", msg0, ", Message 2:", msg1)
        c = send_oracle_command(tn, msg0, msg1)
        print(c, len(c))
        if len(c) == 64: # length of encryption of msg0 is 16 (initial vector) + 16 (actual encryption of)
            guess = 0
        else:
            guess = 1
        print("Guess:", guess)
        ok = send_guess(tn, guess)
        print(ok)
        if "lost" in ok:
            break
    
    print(json_recv(tn)["res"])
    

if __name__ == "__main__":
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50400

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)