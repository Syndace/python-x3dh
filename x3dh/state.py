from __future__ import absolute_import

import base64
from functools import wraps
import hashlib
import os
import time

from .exceptions import InvalidConfigurationException
from .exceptions import SessionInitiationException
from .implementations import KeyPairCurve25519
from .publicbundle import PublicBundle

from xeddsa.implementations import XEdDSA25519

from hkdf import hkdf_expand, hkdf_extract

def changes(f):
    @wraps(f)
    def _changes(*args, **kwargs):
        args[0]._changed = True
        return f(*args, **kwargs)
    return _changes

class State(object):
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
        max_num_otpks,
        encryption_key_encoder_class
    ):
        """
        info_string: An ASCII string identifying the application
        curve: 25519 (448 might follow soon)
        hash_function:
            A 256 or 512-bit hash function (e.g. SHA-256 or SHA-512).
            Any key of State.HASH_FUNCTIONS.
        spk_timeout: Rotate the SPK after this amount of seconds
        min_num_otpks: Minimum number of OTPKs that must be available
        max_num_otpks: Maximum number of OTPKs that may be available
        encryption_key_encoder_class: A sub class of EncryptionKeyEncoder
        """

        if not hash_function in State.HASH_FUNCTIONS:
            raise InvalidConfigurationException(
                "Invalid hash function parameter specified. " +
                "Allowed values: Any key of State.HASH_FUNCTIONS"
            )

        if not curve in [ "25519" ]:
            raise InvalidConfigurationException(
                "Invalid curve parameter specified. " +
                "Allowed values: 25519 (448 might follow soon)"
            )

        self.__info_string   = info_string
        self.__curve         = curve
        self.__hash_function = State.HASH_FUNCTIONS[hash_function]
        self.__spk_timeout   = spk_timeout
        self.__min_num_otpks = min_num_otpks
        self.__max_num_otpks = max_num_otpks
        self.__EncryptionKeyEncoder = encryption_key_encoder_class

        # Load the configuration
        if self.__curve == "25519":
            self.__EncryptionKeyPair = KeyPairCurve25519

            self.__XEdDSA = XEdDSA25519

        # Track whether this State has somehow changed since loading it
        # This can be used e.g. to republish the public bundle if something has changed
        self._changed = False

        # Keep a list of OTPKs that have been hidden from the public bundle.
        self.__hidden_otpks = []

        self.__generateIK()
        self.__generateSPK()
        self.__generateOTPKs()

    #################
    # serialization #
    #################

    def serialize(self):
        """
        Return a serializable Python structure, which contains all the state information
        of this object.
        Use together with the fromSerialized method.
        Here, "serializable" means, that the structure consists of any combination of the
        following types:
        - dictionaries
        - lists
        - strings
        - integers
        - floats
        - booleans
        - None
        """

        spk = {
            "key"       : self.__spk["key"].serialize(),
            "signature" : base64.b64encode(self.__spk["signature"]).decode("US-ASCII"),
            "timestamp" : self.__spk["timestamp"]
        }

        return {
            "changed"      : self._changed,
            "ik"           : self.__ik.serialize(),
            "spk"          : spk,
            "otpks"        : [ x.serialize() for x in self.__otpks ],
            "hidden_otpks" : [ x.serialize() for x in self.__hidden_otpks ]
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        """
        Return a new instance that was set to the state that was saved into the serialized
        object.
        Use together with the serialize method.
        Notice: You have to pass all positional parameters required by the constructor of
        the class you call fromSerialized on.
        """

        self = cls(*args, **kwargs)

        parseKeyPair = self.__EncryptionKeyPair.fromSerialized

        self._changed = serialized["changed"]

        self.__ik = parseKeyPair(serialized["ik"])

        spk = serialized["spk"]
        self.__spk = {
            "key"       : parseKeyPair(spk["key"]),
            "signature" : base64.b64decode(spk["signature"].encode("US-ASCII")),
            "timestamp" : spk["timestamp"]
        }

        self.__otpks        = [ parseKeyPair(x) for x in serialized["otpks"] ]
        self.__hidden_otpks = [ parseKeyPair(x) for x in serialized["hidden_otpks"] ]

        return self

    ##################
    # key generation #
    ##################
    
    @changes
    def __generateIK(self):
        """
        Generate an IK. This should only be done once.
        """

        self.__ik = self.__EncryptionKeyPair.generate()
    
    @changes
    def __generateSPK(self):
        """
        Generate a new PK and sign its encryption key using the IK,
        add the timestamp aswell to allow for periodic rotations.
        """

        key = self.__EncryptionKeyPair.generate()

        key_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(
            key.enc,
            self.__curve
        )

        signature = self.__XEdDSA(mont_priv = self.__ik.dec).sign(key_serialized)

        self.__spk = {
            "key": key,
            "signature": signature,
            "timestamp": time.time()
        }

    @changes
    def __generateOTPKs(self, num_otpks = None):
        """
        Generate the given amount of OTPKs.
        If the value of num_otpks is None, set it to the max_num_otpks value of the
        configuration.
        """

        if num_otpks == None:
            num_otpks = self.__max_num_otpks
        
        otpks = []

        for _ in range(num_otpks):
            otpks.append(self.__EncryptionKeyPair.generate())

        try:
            self.__otpks.extend(otpks)
        except AttributeError:
            self.__otpks = otpks

    ####################
    # internal helpers #
    ####################

    def __kdf(self, secret_key_material):
        salt = b"\x00" * self.__hash_function().digest_size

        if self.__curve == "25519":
            input_key_material = b"\xFF" * 32
        if self.__curve == "448":
            input_key_material = b"\xFF" * 57

        input_key_material += secret_key_material

        return hkdf_expand(
            hkdf_extract(salt, input_key_material, self.__hash_function),
            self.__info_string.encode("ASCII"),
            32,
            self.__hash_function
        )

    ##################
    # key management #
    ##################

    def __checkSPKTimestamp(self):
        """
        Check whether the SPK is too old and generate a new one in that case.
        """

        if time.time() - self.__spk["timestamp"] > self.__spk_timeout:
            self.__generateSPK()

    def __refillOTPKs(self):
        """
        If the amount of available OTPKs fell under the minimum, refills the OTPKs up to
        the maximum limit again.
        """

        remainingOTPKs = len(self.__otpks)

        if remainingOTPKs < self.__min_num_otpks:
            self.__generateOTPKs(self.__max_num_otpks - remainingOTPKs)

    @changes
    def hideFromPublicBundle(self, otpk_enc):
        """
        Hide a one-time pre key from the public bundle.
        """

        self.__checkSPKTimestamp()

        for otpk in self.__otpks:
            if otpk.enc == otpk_enc:
                self.__otpks.remove(otpk)
                self.__hidden_otpks.append(otpk)
                self.__refillOTPKs()

    @changes
    def deleteOTPK(self, otpk_enc):
        """
        Delete one-time pre key.
        """

        self.__checkSPKTimestamp()

        for otpk in self.__otpks:
            if otpk.enc == otpk_enc:
                self.__otpks.remove(otpk)

        for otpk in self.__hidden_otpks:
            if otpk.enc == otpk_enc:
                self.__hidden_otpks.remove(otpk)

        self.__refillOTPKs()

    ############################
    # public bundle management #
    ############################

    def getPublicBundle(self):
        """
        Fill a PublicBundle object with the public bundle data of this State.
        """

        self.__checkSPKTimestamp()

        ik_enc  = self.__ik.enc
        spk_enc = self.__spk["key"].enc
        spk_sig = self.__spk["signature"]
        otpk_encs = [ otpk.enc for otpk in self.__otpks ]

        return PublicBundle(ik_enc, spk_enc, spk_sig, otpk_encs)

    @property
    def changed(self):
        """
        Read, whether this State has changed since it was loaded/since this flag was last
        cleared.

        Clears the flag when reading.
        """

        self.__checkSPKTimestamp()

        changed = self._changed
        self._changed = False
        return changed

    ######################
    # session initiation #
    ######################

    def initSessionActive(
        self,
        other_public_bundle,
        allow_zero_otpks = False,
        _DEBUG_ek = None
    ):
        self.__checkSPKTimestamp()

        other_ik = self.__EncryptionKeyPair(enc = other_public_bundle.ik)

        other_spk = {
            "key": self.__EncryptionKeyPair(enc = other_public_bundle.spk),
            "signature": other_public_bundle.spk_signature
        }

        other_otpks = [
            self.__EncryptionKeyPair(enc = otpk) for otpk in other_public_bundle.otpks
        ]

        if len(other_otpks) == 0 and not allow_zero_otpks:
            raise SessionInitiationException(
                "The other public bundle does not contain any OTPKs, which is not allowed"
            )

        other_spk_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(
            other_spk["key"].enc,
            self.__curve
        )

        if not self.__XEdDSA(mont_pub = other_ik.enc).verify(
            other_spk_serialized,
            other_spk["signature"]
        ):
            raise SessionInitiationException(
                "The signature of this public bundle's spk could not be verifified"
            )

        if _DEBUG_ek == None:
            ek = self.__EncryptionKeyPair.generate()
        else:
            import logging

            logging.getLogger("x3dh.State").error(
                "WARNING: RUNNING UNSAFE DEBUG-ONLY OPERATION"
            )

            ek = _DEBUG_ek

        dh1 = self.__ik.getSharedSecret(other_spk["key"])
        dh2 = ek.getSharedSecret(other_ik)
        dh3 = ek.getSharedSecret(other_spk["key"])
        dh4 = b""

        otpk = None
        if len(other_otpks) > 0:
            otpk_index = ord(os.urandom(1)) % len(other_otpks)
            otpk = other_otpks[otpk_index]

            dh4 = ek.getSharedSecret(otpk)

        sk = self.__kdf(dh1 + dh2 + dh3 + dh4)

        ik_enc_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(
            self.__ik.enc,
            self.__curve
        )

        other_ik_enc_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(
            other_ik.enc,
            self.__curve
        )

        ad = ik_enc_serialized + other_ik_enc_serialized

        return {
            "to_other": {
                "ik": self.__ik.enc,
                "ek": ek.enc,
                "otpk": otpk.enc if otpk else None,
                "spk": other_spk["key"].enc
            },
            "ad": ad,
            "sk": sk
        }

    def initSessionPassive(
        self,
        session_init_data,
        allow_no_otpk = False,
        keep_otpk = False
    ):
        """
        The specification of X3DH dictates to delete the one time pre keys as soon as
        they are used.

        This behaviour provides security but may lead to considerable usability downsides
        in some environments.

        For that reason the keep_otpk flag exists.
        If set to True, the one time pre key is not automatically deleted.
        USE WITH CARE, THIS MAY INTRODUCE SECURITY LEAKS IF USED INCORRECTLY.
        If you decide set the flag and to keep the otpks, you have to manage deleting them
        yourself, e.g. by subclassing this class and overriding this method.
        """

        self.__checkSPKTimestamp()

        other_ik = self.__EncryptionKeyPair(enc = session_init_data["ik"])
        other_ek = self.__EncryptionKeyPair(enc = session_init_data["ek"])

        if self.__spk["key"].enc != session_init_data["spk"]:
            raise SessionInitiationException(
                "The SPK used for this session initialization has been rotated, " +
                "the session can not be initiated"
            )

        my_otpk = None
        if "otpk" in session_init_data:
            for otpk in self.__otpks:
                if otpk.enc == session_init_data["otpk"]:
                    my_otpk = otpk
                    break

            for otpk in self.__hidden_otpks:
                if otpk.enc == session_init_data["otpk"]:
                    my_otpk = otpk
                    break

            if not my_otpk:
                raise SessionInitiationException(
                    "The OTPK used for this session initialization has been deleted, " +
                    "the session can not be initiated"
                )
        elif not allow_no_otpk:
            raise SessionInitiationException(
                "This session initialization data does not contain an OTPK, " +
                "which is not allowed"
            )

        dh1 = self.__spk["key"].getSharedSecret(other_ik)
        dh2 = self.__ik.getSharedSecret(other_ek)
        dh3 = self.__spk["key"].getSharedSecret(other_ek)
        dh4 = b""
        
        if my_otpk:
            dh4 = my_otpk.getSharedSecret(other_ek)

        sk = self.__kdf(dh1 + dh2 + dh3 + dh4)

        other_ik_enc_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(
            other_ik.enc,
            self.__curve
        )

        ik_enc_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(
            self.__ik.enc,
            self.__curve
        )

        ad = other_ik_enc_serialized + ik_enc_serialized

        if my_otpk and not keep_otpk:
            self.deleteOTPK(my_otpk.enc)

        return {
            "ad": ad,
            "sk": sk
        }

    @property
    def spk(self):
        self.__checkSPKTimestamp()

        return self.__spk["key"]

    @property
    def spk_signature(self):
        self.__checkSPKTimestamp()

        return self.__spk["signature"]

    @property
    def ik(self):
        self.__checkSPKTimestamp()

        return self.__ik

    @property
    def otpks(self):
        self.__checkSPKTimestamp()

        return self.__otpks

    @property
    def hidden_otpks(self):
        self.__checkSPKTimestamp()

        return self.__hidden_otpks
