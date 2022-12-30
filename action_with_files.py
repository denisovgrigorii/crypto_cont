from base64 import urlsafe_b64encode


class ActionWithFile:
    @staticmethod
    def save_in_file(data, name):
        with open(name, 'wb') as file:
            file.write(urlsafe_b64encode(data))

    @staticmethod
    def read_crypto_file(file):
        with open(file, "rb") as file:
            return file.read()

    @staticmethod
    def check_repetition_secret(decrypt_data, cred_name):
        print('Окей, проверим, вдруг такой секрет уже есть в базе...')
        if decrypt_data.get(cred_name) is None:
            print('Секрет не найден в базе, сохраняю...')
            return 'cred not found in data'
        print(f'Секрет {cred_name} уже существует, если хотите его обновить запустите скрипт с параметром update')
