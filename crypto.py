from os import urandom
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet, InvalidToken
from json import loads


class ActionCrypto:
    @staticmethod
    def create_crypto_key(salt, password_str):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=salt,
                         iterations=100000,
                         )

        key = urlsafe_b64encode(kdf.derive(password_str.encode()))
        return key

    def crypt_file(self, data_file_crypt, password_str):
        salt = urandom(32)
        key = self.create_crypto_key(salt, password_str)
        print('шифрую с этими значениями')
        print(salt)
        print(password_str.encode())
        print(key)
        return Fernet(key).encrypt(data_file_crypt.encode()), salt

    def decrypt_file(self, password_str, salt, data_to_decrypt):
        key = self.create_crypto_key(urlsafe_b64decode(salt), password_str)
        print('расшифровываю с этими значениями')
        print(urlsafe_b64decode(salt))
        print(password_str.encode())
        print(key)
        try:
            return loads(Fernet(key).decrypt(data_to_decrypt))
        except InvalidToken:
            return 'invalid pwd'
