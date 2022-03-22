from telnetlib import Telnet
import json
from Crypto.Random import get_random_bytes


def json_recv(tn: Telnet):
    line = tn.read_until(b"\n")
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req: dict):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


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
    if len(res) > 96*2:
        return True
    return False


def get_initial_ciphertext(tn: Telnet):
    """Gets a ciphertext of a correctly decrypted command including the flag.
    
    Note here that the server responds with a correctly padded and encoded 
    message and thus reflecting this message gets us the ciphertext with a flag

    Args:
        tn (Telnet): a telnet client

    Returns:
        str: ciphertext including flag
    """
    rand_command = get_random_bytes(32)
    json_send(tn, {"command": rand_command.hex()})
    res = json_recv(tn)["res"]
    json_send(tn, {"command": res})
    res = json_recv(tn)["res"]
    print(len(res))
    return res


def byte_xor(a: bytes, b: bytes):
    """Performs bytewise xor of two equal length byte arrays

    Args:
        a (bytes): the first byte array
        b (bytes): the second byte array
    """
    return bytearray([x ^ y for x, y in zip(a, b)])


def attack(tn: Telnet):
    """Performs the attack

    The attack works the same way as in exercise m3. But in this exercise the whole 
    plaintext is decrypted by repeating the attack for every block. Note that the last
    block of the ciphertext is not considered for two reasons:
      1) By looking at the server code, we see that the flag is never part of 
         the last block
      2) The last block requires special handling as it contains padding

    Args:
        tn (Telnet): a telnet client
    """
    ciphertext = bytes.fromhex(get_initial_ciphertext(tn))
    plaintext = bytearray(len(ciphertext) - 32)
    num_blocks = int(len(plaintext)/16)

    for k in range(0, len(ciphertext)-32, 16):
        delta_success = bytearray(16)
        for i in range(1, 17):
            delta = byte_xor(delta_success, bytes(16-i+1) + bytes((i-1)*[i]))
            for j in range(256):
                delta[-i] = j
                if is_padding_correct(tn, ciphertext[:k] + byte_xor(ciphertext[k:k+16], delta) + ciphertext[k+16:k+32]):
                    delta_success[-i] = delta[-i] ^ (i)
                    break
        plaintext[k:k+16] = delta_success
        print(f"Successfully decrypted block {int(k/16 + 1)} of {num_blocks}")
    print(plaintext)


def main():
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50404

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
