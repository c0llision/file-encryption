#!/usr/bin/env python3
'''Author: c0llision '''
import os
import json
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_CIPHER = 'fernetAES'
DEFAULT_KDF_TIME_MS = 500
PBKDF_MIN_ITERATIONS = 10000
SCRYPT_MIN_ITERATIONS = 14
DEFAULT_KDF = 'scrypt'


def _encrypt(data, cipher, key):
    if cipher.lower() == 'fernetaes':
        key = urlsafe_b64encode(key)
        out = Fernet(key).encrypt(data.encode('utf-8'))
    else:
        raise Exception('Unknown cipher')

    return out.decode('utf-8')


def _decrypt(data, cipher, key):
    if cipher.lower() == 'fernetaes':
        key = urlsafe_b64encode(key)
        out = Fernet(key).decrypt(data.encode('utf-8'))
    else:
        raise Exception('Unknown cipher')

    return out.decode('utf-8')


def encrypt_data(data, passw, cipher=DEFAULT_CIPHER, kdf_algo=DEFAULT_KDF,
                 iterations=False):

    salt = gen_salt()
    if not iterations:
        iterations = bench_kdf(kdf=kdf_algo)

    key = derive_key(passw, salt, kdf_algo, iterations)
    data = _encrypt(data, cipher, key)

    out = {
        'encrypted': True,
        'cipher': cipher,
        'kdf': kdf_algo,
        'iterations': iterations,
        'salt': urlsafe_b64encode(salt).decode('utf-8'),
        'data': data
    }

    return json.dumps(out, indent=4)


def decrypt_data(obj, passw):
    obj = json.loads(obj)
    if not obj['encrypted']:
        return obj['data']

    salt = urlsafe_b64decode(obj['salt'])
    key = derive_key(passw, salt, obj['kdf'], obj['iterations'])
    return _decrypt(obj['data'], obj['cipher'], key)


def bench_kdf(kdf, target_ms=DEFAULT_KDF_TIME_MS):
    if kdf.lower() == 'pbkdf':
        kdf_iterations = 100000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt',
            iterations=100000,
            backend=default_backend()
        )

        start = time.time()
        kdf.derive(b'pass')
        end = time.time()
        elapsed = float((end - start))
        iterations = round((target_ms/1000) / elapsed * kdf_iterations)

        return max(iterations, PBKDF_MIN_ITERATIONS)

    elif kdf.lower() == 'scrypt':
        kdf_iterations = 14
        kdf = Scrypt(
            salt=b'salt',
            length=32,
            n=2**kdf_iterations,
            r=8,
            p=1,
            backend=default_backend()
        )

        start = time.time()
        kdf.derive(b'pass')
        end = time.time()
        elapsed = float((end - start))

        x = round((target_ms/1000) / elapsed)
        i = 0
        while x > 1:
            x /= 2
            i += 1
        iterations = kdf_iterations + i

        return max(iterations, SCRYPT_MIN_ITERATIONS)

    else:
        raise Exception('Unknown KDF:', kdf)


def gen_salt():
    return os.urandom(8)


def derive_key(passw, salt, kdf_algo, iterations):
    kdf_algo = kdf_algo.lower()
    if kdf_algo == 'pbkdf':
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )

    elif kdf_algo == 'scrypt':
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**iterations,
            r=8,
            p=1,
            backend=default_backend()
        )
    else:
        raise Exception('unknown kdf algorithm:', kdf_algo)

    return kdf.derive(passw.encode('utf-8'))


def main():
    password = 'mypassword123'
    filename = 'test'

    # encrypt
    ciphertext = encrypt_data('secret message', password)
    print(ciphertext)

    # write encrypted data to file
    with open(filename, 'w') as f:
        f.write(ciphertext)

    # decrypt
    cleartext = decrypt_data(ciphertext, password)
    print(cleartext)

    # decrypt data from file
    with open(filename, 'r') as f:
        ciphertext2 = f.read()
    cleartext2 = decrypt_data(ciphertext2, password)
    print(cleartext2)


if __name__ == '__main__':
    main()
