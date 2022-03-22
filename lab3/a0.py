def pad(b: bytes, block_length: int):
    k = block_length - len(b) % block_length
    return b + bytes([k]*k)

def unpad(b: bytes, block_length: int):
    if len(b) == 0 or len(b) % block_length != 0:
        raise ValueError()

    padding_length = b[-1]
    if b[-padding_length:] != bytes([padding_length]*padding_length):
        raise ValueError()
    return b[:-padding_length]

def main():
    padded_flag = pad(b'flag', 16)
    print(padded_flag.hex())
    print(unpad(padded_flag, 16))

if __name__ == '__main__':
    main()