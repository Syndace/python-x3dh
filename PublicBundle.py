class PublicBundle(object):
    def __init__(self, ik, spk, spk_signature, otpks):
        self.__ik = ik
        self.__spk = spk
        self.__spk_signature = spk_signature
        self.__otpks = otpks

    @property
    def ik(self):
        return self.__ik

    @property
    def spk(self):
        return self.__spk

    @property
    def spk_signature(self):
        return self.__spk_signature

    @property
    def otpks(self):
        return self.__otpks
