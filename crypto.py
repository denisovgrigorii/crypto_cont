from os import urandom
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet, InvalidToken
from json import loads


class InvalidPwdError(Exception):
    def __str__(self):
        return 'Неудалось расшифровать файл, пожалуйста введите корректный пароль!'


class ActionCrypto:
    def create_crypto_key(self, salt, password_str) -> str:
        """Create sha256 key for crypt.
        Args:
            salt(str): salt for create sha256 kdf.
            password_str(str): password for create key.
        Returns:
            str: Key for create crypto data.
        """
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
        return Fernet(key).encrypt(data_file_crypt.encode()), salt

    def decrypt_file(self, password_str, salt, data_to_decrypt):
        key = self.create_crypto_key(urlsafe_b64decode(salt), password_str)
        try:
            return loads(Fernet(key).decrypt(data_to_decrypt))
        except InvalidToken:
            raise InvalidPwdError
