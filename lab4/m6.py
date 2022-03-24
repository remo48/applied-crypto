from telnetlib import Telnet
import json
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


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

    First decrypt a random block with a iv containing only 0x00 bytes. We then compute
    a value iv', which xor'd with the plaintext results in the last block of the command.
    By repeating this process with iv' as the ciphertext, we ultimately forge a encryption
    of the command 

    Args: 
        tn (Telnet): a telnet client

    Returns:
        str: a ciphertext including the flag
    """
    command = pad(b"flag_hey_there_oh_noes_block_boundaries_rip", 16)
    encrypted_command = bytearray(len(command))
    ciphertext = get_random_bytes(16)
    for i in range(len(command), 0, -16):
        encrypted_command[i-16:i] = ciphertext
        plaintext = decrypt_block(tn, bytes(16), ciphertext)
        ciphertext = byte_xor(plaintext, command[i-16:i])
        print(
            f"Successfully forged block {(len(command)-i)//16 + 1} of {len(command)//16}")
    json_send(tn, {"command": (ciphertext + encrypted_command).hex()})
    return json_recv(tn)["res"]


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

    First get a ciphertext inlcuding the flag and then decrypt it.

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
    remote = True

    if remote:
        HOSTNAME = "aclabs.ethz.ch"
        PORT = 50406
    else:
        HOSTNAME = "localhost"
        PORT = 50406

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)


if __name__ == '__main__':
    main()
