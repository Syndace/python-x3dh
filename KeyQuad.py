class KeyQuad(object):
    @classmethod
    def fromQuad(cls, public_key = None, secret_key = None, signing_key = None, verifying_key = None):
        raise NotImplementedError

    @classmethod
    def generate(cls):
        raise NotImplementedError

    @classmethod
    def fromSerializable(cls, data):
        """
        Load a KeyQuad form a serializable structure as created by toSerializable.
        """

        raise NotImplementedError

    def toSerializable(self):
        """
        Create a serializable data structure from this KeyQuad, which can be e.g. dumped as JSON.
        Creates a simple python dict which contains the key data in base64 encoding.
        NOTE: The structure returned by this method may contain secret data! Use it carefully.
        """

        raise NotImplementedError

    @property
    def pub(self):
        raise NotImplementedError

    @property
    def sec(self):
        raise NotImplementedError

    @property
    def sig(self):
        raise NotImplementedError

    @property
    def ver(self):
        raise NotImplementedError

    def sign(self, data):
        raise NotImplementedError

    def verify(self, data, signature):
        raise NotImplementedError

    def getSharedSecret(self, other):
        raise NotImplementedError
