#!/usr/bin/env python3
'''Author: c0llision '''
import unittest
from main import *


class Test(unittest.TestCase):
    def test(self):
        password = 'mypassword123'
        secret = 'secret message'

        ciphertext = encrypt_data(secret, password)
        cleartext = decrypt_data(ciphertext, password)

        self.assertEqual(secret, cleartext)

    def test_scrypt(self):
        password = 'mypassword123'
        salt = b'123456'
        kdf_algo = 'scrypt'
        iterations = 14
        expected_key = b'\xf5W\xc6f\xab\xb1\x9d\x8e\x80a\xb9\xfa\xb3t\xd1\x00\xe9\x80"d\x9e\xa9v0w\x01\x91\xa4\xbc.7\xec'

        key = derive_key(password, salt, kdf_algo, iterations)
        self.assertEqual(key, expected_key)

    def test_pbkdf(self):
        password = 'mypassword123'
        salt = b'123456'
        kdf_algo = 'pbkdf'
        iterations = 10000
        expected_key = b'\x80\x86l)o\xc2n\xc6\xb3H\x8b\xf6{,\xa8\n]\xe14\xd7^\xe9\xaa\xcf\x05_\xaf_\x18r\xf1R'

        key = derive_key(password, salt, kdf_algo, iterations)
        self.assertEqual(key, expected_key)


if __name__ == '__main__':
    unittest.main()