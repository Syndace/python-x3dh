from __future__ import absolute_import

from .serializable import Serializable

class KeyPair(Serializable):
    """
    The interface of a key pair. A key pair is a pair consisting of a private and a public
    key used for en- and decryption.
    """

    def __init__(self, priv = None, pub = None):
        """
        Initiate a KeyPair instance using the key information provided as parameters.

        :param priv: The private key as a bytes-like object or None.
        :param pub: The public key as a bytes-like object or None.
        """

        raise NotImplementedError

    @classmethod
    def generate(cls):
        """
        :returns: A new key pair with private and public key set.
        """

        raise NotImplementedError

    @property
    def priv(self):
        """
        :returns: A bytes-like object encoding the private key of this key pair instance.
        """

        raise NotImplementedError

    @property
    def pub(self):
        """
        :returns: A bytes-like object encoding the public key of this key pair instance.
        """

        raise NotImplementedError

    def encrypt(self, data, other):
        """
        Encrypt given data using the private key stored by this KeyPair instance, for the
        public key stored by the other instance.

        :param data: The data to encrypt. A bytes-like object.
        :param other: An instance of the KeyPair class. The public key to encrypt the data
            for.
        :returns: The encrypted data.
        :raises MissingKeyException: If any key is missing to complete this operation. The
            exception message will contain (human-readable) details.
        """

        raise NotImplementedError

    def decrypt(self, data, other):
        """
        Decrypt the encrypted data using the private key stored by this KeyPair instance,
        for the public key stored by the other instance.

        :param data: The data to decrypt. A bytes-like object.
        :param other: An instance of the KeyPair class. The public key to decrypt the data
            from.
        :returns: The decrypted plain data.
        :raises MissingKeyException: If any key is missing to complete this operation. The
            exception message will contain (human-readable) details.
        """

        raise NotImplementedError

    def getSharedSecret(self, other):
        """
        Get a shared secret between the keys stored by this instance and the keys stored
        by the other instance.

        The shared secrets are generated, so that following equation is True: ::

            shared_secret(A.priv, B.pub) == shared_secret(B.priv, A.pub)

        :param other: An instance of the KeyPair class.
        :returns: The shared secret, as a bytes-like object.
        :raises MissingKeyException: If any key is missing to complete this operation. The
            exception message will contain (human-readable) details.
        """

        raise NotImplementedError
