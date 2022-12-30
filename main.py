from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode
from json import dumps, loads
from getpass import getpass
import argparse


class InvalidPwdError(Exception):
    def __str__(self):
        return 'Неудалось расшифровать файл, пожалуйста введите корректный пароль!'


class NotFoundCredError(Exception):
    def __str__(self):
        return 'Указанный Вами секрет отсуствует в архиве, проверьте корректность параметров запуска.'


class InterfaceAction:
    @staticmethod
    def input_cred_passwd():
        return getpass("Введите пароль для секрета: ")

    @staticmethod
    def input_cred_name(action):
        if action == 'create':
            return input("Введите название секрета: ")
        return input("Введите имя секрета, который ходите найти в базе: ")

    @staticmethod
    def confirm_create_secret():
        return input("Хотите сохранить секрет?  [YES\\NO]")


def init_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('file_dir', type=str, help='directory file')
    parser.add_argument('action', type=str, help='action do it ')
    return parser.parse_args()


def crypt_file(data_file_crypt, password_str):
    salt = urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000,
                     )

    key = urlsafe_b64encode(kdf.derive(password_str.encode()))
    f = Fernet(key)
    print('шифрую с этими значениями')
    print(salt)
    print(password_str.encode())
    print(key)
    return f.encrypt(data_file_crypt.encode()), salt


def save_in_file(data, name):
    with open(name, 'wb') as file:
        file.write(urlsafe_b64encode(data))


def read_crypto_file(file):
    with open(file, "rb") as file:
        return file.read()


def decrypt(pwd_str, salt, data_to_decrypt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=urlsafe_b64decode(salt),
                     iterations=100000,
                     )
    key = urlsafe_b64encode(kdf.derive(pwd_str.encode()))
    f = Fernet(key)
    print('расшифровываю с этими значениями')
    print(urlsafe_b64decode(salt))
    print(pwd_str.encode())
    print(key)
    try:
        return loads(f.decrypt(data_to_decrypt))
    except InvalidToken:
        return 'invalid pwd'


def check_repetition_secret(decrypt_data, cred_name):
    print('Окей, проверим, вдруг такой секрет уже есть в базе...')
    if decrypt_data.get(cred_name) is None:
        print('Секрет не найден в базе, сохраняю...')
        return '=============cred not found in DB============='
    return '=============cred found in DB============='


def main_start(args, input_pwd):
    data = read_crypto_file(args.file_dir)
    salt = read_crypto_file("key")
    result_decrypt = decrypt(input_pwd, salt, urlsafe_b64decode(data))
    if result_decrypt == 'invalid pwd':
        raise InvalidPwdError
    print('Хранилище готово к работе!')
    if args.action == 'create':
        print('step create')
        cred_name = InterfaceAction.input_cred_name(args.action)
        cred_passwd = InterfaceAction.input_cred_passwd()
        print(f'Вы создаете секрет с name={cred_name}, pwd={cred_passwd}')
        response_save = InterfaceAction.confirm_create_secret()
        print(response_save)
        if response_save == 'YES':

            print('надо сохранить')
            repetition = check_repetition_secret(result_decrypt, cred_name)
            # if repetition == '=============cred not found in DB=============':
            result_decrypt[cred_name] = cred_passwd
            print(result_decrypt)
            data, salt = crypt_file(dumps(result_decrypt), input_pwd)
            # print(data)
            # print(salt)
            save_in_file(data, args.file_dir)
            save_in_file(salt, 'key')
            # elif repetition == '=============cred found in DB=============':
            # print('Секрет с таким именем уже существует в БД. Если хотите обновнить секрет выберите агумент "update"')
        else:
            print('Окей, ничего не сохраняю.')
    if args.action == 'get':
        print('step get')
        data = read_crypto_file(args.file_dir)
        salt = read_crypto_file("key")
        result_decrypt = decrypt(input_pwd, salt, urlsafe_b64decode(data))
        get_cred = InterfaceAction.input_cred_name(args.action)
        return print(result_decrypt.get(get_cred))
    if args.action == 'all':
        print('step show all')
        print(result_decrypt)


if __name__ == '__main__':
    args = init_args()
    input_password = getpass('Введите пароль: ')
    main_start(args, input_password)

#
#
# dict_data = {'grisha': 'lox', 'vitya': 'ne lox', 'vera': 'privet', 'test': 'tes', '12343413123213': 'pwa', 'dima': '666', 'alesha': 'PWASDFQWE*!@#', 'qweqeqweqw': 'ASD123'}
# data, salt = crypt_file(dumps(dict_data), '123')
# save_in_file(data, 'data')
# save_in_file(salt, 'key')
# data = read_crypto_file('data')
# salt = read_crypto_file('key')
# d= decrypt('123', salt, urlsafe_b64decode(data))
# print(d)
