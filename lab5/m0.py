from Crypto.Hash import MD5, HMAC, SHA1, SHA256
from Crypto.Protocol.KDF import scrypt

PW = '6f6e696f6e732061726520736d656c6c79'
SECRET = '6275742061726520617765736f6d6520f09f988b'
SALT = '696e2061206e69636520736f6666726974746f21'


def onion(pw: bytes, salt: bytes):
    secret = bytes.fromhex(SECRET)
    md5 = MD5.new()
    sha1_hmac = HMAC.new(salt, digestmod=SHA1)
    sha256_hmac_1 = HMAC.new(secret, digestmod=SHA256)
    sha256_hmac_2 = HMAC.new(salt, digestmod=SHA256)

    md5.update(pw)
    sha1_hmac.update(md5.digest())
    sha256_hmac_1.update(sha1_hmac.digest())
    h4 = scrypt(sha256_hmac_1.digest(), salt, key_len=64, N=2**10, r=32, p=2)
    sha256_hmac_2.update(h4).digest()
    return sha256_hmac_2.digest()


if __name__ == '__main__':
    pw = bytes.fromhex(PW)
    salt = bytes.fromhex(SALT)
    print(onion(pw, salt).hex())
