from getpass import getpass


class InterfaceAction:
    """Utility dialog box."""
    @staticmethod
    def input_passwd(step: str) -> str:
        """Secret input password for enter in util or new data.
        Returns:
            str: Secter string for input password.
        """
        if step == 'start':
            return getpass('Введите пароль: ')
        return getpass("Введите пароль для секрета: ")

    @staticmethod
    def input_cred_name(action: str) -> str:
        """Input name secret
        Returns:
            str: String input for name cred.
        """
        if action == 'create':
            return input("Введите название секрета: ")
        return input("Введите имя секрета, который ходите найти в базе: ")

    @staticmethod
    def confirm_create_secret() -> str:
        """Question confirm create cred.
        Returns:
            str: String for confirm create cred.
        """
        return input("Хотите сохранить секрет?  [YES\\NO]")
