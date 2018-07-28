class EncryptionKeyPair(object):
    def __init__(self, enc = None, dec = None):
        raise NotImplementedError

    @classmethod
    def generate(cls):
        raise NotImplementedError

    @property
    def enc(self):
        """
        Return a bytes-like object representing the public encryption key.
        """

        raise NotImplementedError

    @property
    def dec(self):
        """
        Return a bytes-like object representing the private decryption key.
        """

        raise NotImplementedError

    def encrypt(self, data, other):
        raise NotImplementedError

    def decrypt(self, data, other):
        raise NotImplementedError

    def getSharedSecret(self, other):
        raise NotImplementedError
