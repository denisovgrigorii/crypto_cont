from interface_action import InterfaceAction
from crypto import ActionCrypto
from action_with_files import ActionWithFile
from argparse import ArgumentParser
from getpass import getpass
from base64 import urlsafe_b64decode
from json import dumps


def init_args():
    parser = ArgumentParser()
    parser.add_argument('file_dir', type=str, help='directory file')
    parser.add_argument('action', type=str, help='action do it ')
    return parser.parse_args()


def main_start(args, input_pwd):
    data = ActionWithFile.read_crypto_file(args.file_dir)
    salt = ActionWithFile.read_crypto_file('key')
    crypto = ActionCrypto()
    result_decrypt = crypto.decrypt_file(input_pwd, salt, urlsafe_b64decode(data))
    print('Хранилище готово к работе!')
    if args.action == 'create':
        print('step create')
        cred_name = InterfaceAction.input_cred_name(args.action)
        cred_passwd = InterfaceAction.input_cred_passwd()
        print(f'Вы создаете секрет с name={cred_name}, pwd={cred_passwd}')
        response_save = InterfaceAction.confirm_create_secret()
        print(response_save)
        if response_save == 'YES' or 'yes' or 'y':
            check_repetition = ActionWithFile.check_repetition_secret(result_decrypt, cred_name)
            if check_repetition == 'cred not found in data':
                result_decrypt[cred_name] = cred_passwd
                print(result_decrypt)
                data, salt = crypto.crypt_file(dumps(result_decrypt), input_pwd)
                ActionWithFile.save_in_file(data, args.file_dir)
                ActionWithFile.save_in_file(salt, 'key')
        else:
            print('Окей, ничего не сохраняю.')
    if args.action == 'get':
        get_cred = InterfaceAction.input_cred_name(args.action)
        return print(result_decrypt.get(get_cred))
    if args.action == 'all':
        print(result_decrypt)


if __name__ == '__main__':
    args = init_args()
    input_password = getpass('Введите пароль: ')
    main_start(args, input_password)
