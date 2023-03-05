import base64

from Crypto.Cipher import AES

from ihrd.settings import AES_SECRET, AES_IV

key = AES_SECRET.encode("utf8")
iv = AES_IV.encode("utf8")


class AESCipher(object):
    def __init__(self):
        self.iv = None

    def encrypt_token(self, data):
        aes = AES.new(key, AES.MODE_CFB, iv)
        encoded = aes.encrypt(data)
        encoded = base64.b64encode(encoded).decode()
        return encoded

    def decrypt_token(self, encoded):
        decryptor = AES.new(key, AES.MODE_CFB, iv)
        decoded = base64.b64decode(encoded)
        decoded = decryptor.decrypt(decoded).decode()
        return decoded
