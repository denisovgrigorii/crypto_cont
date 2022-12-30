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
