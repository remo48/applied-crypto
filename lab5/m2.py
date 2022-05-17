from Crypto.Hash import MD5

COMMON_PASSWORDS = [
    "12345",
    "123456",
    "12345678",
    "password",
    "000000000111111111122222222223333333333444444444455555555556666"
]

def md5(s: str):
    h = MD5.new()
    h.update(s.encode("utf-8"))
    return h.hexdigest()

if __name__ == '__main__':
    for pw in COMMON_PASSWORDS:
        print(md5(pw))
