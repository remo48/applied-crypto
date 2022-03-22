from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50304)


def send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
    line = tn.read_until(b'\n')
    return json.loads(line.decode())

def main():
    # create new user with a full block of gibberish
    mallory_data = json.dumps({
        "pw" : "password",
        "random": "adghedbciuehbiseda",
    })

    user_request = {
        'command': 'add_user',
        'username': 'mallory',
        'data': mallory_data
    }
    print(send(user_request))

    # backup user and change uid to 0
    backup_request = {
        'command': 'backup_user',
        'username': 'mallory'
    }
    res = send(backup_request)
    backup_len, secure_backup = res['res']
    user_encrypted = bytearray.fromhex(secure_backup)
    user_encrypted[90] = user_encrypted[90]^ord(b'3')^ord(b'0')

    # restore user
    restore_request = {
        'command': 'restore_user',
        'backup_len': backup_len,
        'secure_backup': user_encrypted.hex()
    }
    print(send(restore_request))

    # authenticate with user
    auth_request = {
        'command': 'auth',
        'username': 'mallory',
        'password': 'password'
    }
    print(send(auth_request))

    # get flag
    print(send({'command': 'watch'}))

if __name__ == '__main__':
    main()