class PublicBundle(object):
    def __init__(self, ik, spk, spk_signature, otpks):
        """
        Create a new public bundle.

        :param ik: The public key of the identity key pair, encoded as a bytes-like
            object.
        :param spk: The public key of the signed pre key pair, encoded as a bytes-like
            object.
        :param spk_signature: A bytes-like object encoding the signature, that was created
            by signing the public key of the signed pre key pair using the identity key.
        :param otpks: A list of public keys, one for each one-time pre key pair, each
            encoded as a bytes-like object.
        """

        self.__ik = ik
        self.__spk = spk
        self.__spk_signature = spk_signature
        self.__otpks = otpks

    @property
    def ik(self):
        """
        :returns: The public key of the identity key pair, encoded as a bytes-like object.
        """

        return self.__ik

    @property
    def spk(self):
        """
        :returns: The public key of the signed pre key pair, encoded as a bytes-like
            object.
        """

        return self.__spk

    @property
    def spk_signature(self):
        """
        :returns: A bytes-like object encoding the signature, that was created by signing
            the public key of the signed pre key pair using the identity key.

        """

        return self.__spk_signature

    @property
    def otpks(self):
        """
        :returns: A list of public keys, one for each one-time pre key pair, each encoded
            as a bytes-like object.
        """

        return self.__otpks
