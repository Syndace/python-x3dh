from __future__ import absolute_import

import hashlib

from .exceptions import InvalidConfigurationException

class Config(object):
    HASH_FUNCTIONS = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512
    }

    def __init__(
        self,
        info_string,
        curve,
        hash_function,
        spk_timeout,
        min_num_otpks,
        max_num_otpks
    ):
        """
        info_string: An ASCII string identifying the application
        curve: 25519 (448 might follow soon)
        hash_function:
            A 256 or 512-bit hash function (e.g. SHA-256 or SHA-512).
            Any key of Config.HASH_FUNCTIONS.
        spk_timeout: Rotate the SPK after this amount of seconds
        min_num_otpks: Minimum number of OTPKs that must be available
        max_num_otpks: Maximum number of OTPKs that may be available
        """

        if not hash_function in Config.HASH_FUNCTIONS:
            raise InvalidConfigurationException(
                "Invalid hash function parameter specified. " +
                "Allowed values: Any key of Config.HASH_FUNCTIONS"
            )

        if not curve in [ "25519" ]:
            raise InvalidConfigurationException(
                "Invalid curve parameter specified. " +
                "Allowed values: 25519 (448 might follow soon)"
            )

        self.__info_string   = info_string
        self.__curve         = curve
        self.__hash_function = hash_function
        self.__spk_timeout   = spk_timeout
        self.__min_num_otpks = min_num_otpks
        self.__max_num_otpks = max_num_otpks

    @property
    def info_string(self):
        return self.__info_string

    @property
    def curve(self):
        return self.__curve

    @property
    def hash_function(self):
        return Config.HASH_FUNCTIONS[self.__hash_function]

    @property
    def spk_timeout(self):
        return self.__spk_timeout

    @property
    def min_num_otpks(self):
        return self.__min_num_otpks

    @property
    def max_num_otpks(self):
        return self.__max_num_otpks
