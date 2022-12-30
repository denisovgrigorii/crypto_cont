from getpass import getpass


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
