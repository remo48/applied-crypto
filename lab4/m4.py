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


def get_encrypted_flag(tn: Telnet):
    """Gets a ciphertext from the oracle including the flag. 

    Note here that the server first responds with a correctly padded and encoded 
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
    return res


def byte_xor(a: bytes, b: bytes):
    """Performs bytewise xor of two equal length byte arrays

    Args:
        a (bytes): the first byte array
        b (bytes): the second byte array

    Returns:
        bytearray: xor of the two byte arrays a and b
    """
    return bytearray([x ^ y for x, y in zip(a, b)])


def decrypt_block(tn: Telnet, iv: bytes, block: bytes):
    """Decrypts a block of ciphertext given an initialization vector iv and the 
    encrypted block

    Args:
        tn (Telnet): a telnet client
        iv (bytes): initialization vector
        block (bytes): the ciphertext block to decrypt

    Returns:
        bytearray: the decryption of the block
    """
    delta_success = bytearray(16)
    for i in range(1, 17):
        delta = byte_xor(delta_success, bytes(16-i+1) + bytes((i-1)*[i]))
        for j in range(256):
            delta[-i] = j ^ i
            if is_padding_correct(tn, byte_xor(iv, delta) + block):
                # Make sure that the padding is 0x01. If another padding (i.e. 0x02 0x02) was accepted by the oracle,
                # this additional check would detect it
                if i < 16:
                    delta[-i-1] = (delta[-i-1] + 1) % 256
                    if not is_padding_correct(tn, byte_xor(iv, delta) + block):
                        continue
                delta_success[-i] = j
                break
    return delta_success


def attack(tn: Telnet):
    """Performs the attack

    The attack works the same way as in exercise m3. But in this exercise the whole 
    plaintext is decrypted by repeating the attack for every block.

    Args:
        tn (Telnet): a telnet client
    """
    ciphertext = bytes.fromhex(get_encrypted_flag(tn))
    plaintext = ""
    num_blocks = len(ciphertext)//16 - 1

    for k in range(0, len(ciphertext)-16, 16):
        for c in decrypt_block(tn, ciphertext[k:k+16], ciphertext[k+16:k+32]):
            plaintext += chr(c)
        print(f"Successfully decrypted block {int(k/16 + 1)} of {num_blocks}")
    print(plaintext)


def main():
    HOSTNAME = "aclabs.ethz.ch"
    PORT = 50404

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
