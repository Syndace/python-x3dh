from __future__ import absolute_import

import base64
from functools import wraps
import os
import time

from .config import Config
from .publicbundle import PublicBundle
from .exceptions import SessionInitiationException

from scci.implementations import KeyQuad25519
from xeddsa.implementations import XEdDSA25519

from hkdf import hkdf_expand, hkdf_extract

def changes(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        args[0]._changed = True
        return f(*args, **kwargs)
    return wrapper

class State(object):
    def __init__(self, configuration, encryptionKeyEncoder):
        # Track whether this State has somehow changed since loading it
        # This can be used e.g. to republish the public bundle if something has changed
        self._changed = False

        # Load the configuration
        self.__config = configuration

        if self.__config.curve == "25519":
            self.__KeyQuad = KeyQuad25519
            self.__XEdDSA = XEdDSA25519

        self.__EncryptionKeyEncoder = encryptionKeyEncoder

        self.__hidden_otpks = []

        self.__generateIK()
        self.__generateSPK()
        self.__generateOTPKs()

    def __kdf(self, secret_key_material):
        salt = b"\x00" * self.__config.hash_function().digest_size

        if self.__config.curve == "25519":
            input_key_material = b"\xFF" * 32
        #if self.__config.curve == "448":
        #    input_key_material = b"\xFF" * 57

        input_key_material += secret_key_material

        return hkdf_expand(hkdf_extract(salt, input_key_material, self.__config.hash_function), self.__config.info_string.encode("ASCII"), 32, self.__config.hash_function)

    @changes
    def __generateIK(self):
        """
        Generate an IK. This should only be done once.
        """

        self.__ik = self.__KeyQuad.generate()
    
    @changes
    def __generateSPK(self):
        """
        Generate a new PK and sign its encryption key using the IK, add the timestamp aswell to allow for periodic rotations.
        """

        key = self.__KeyQuad.generate()

        key_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(key.enc, self.__config.curve)

        signature = self.__XEdDSA(decryption_key = self.__ik.dec).sign(key_serialized, os.urandom(64))

        self.__spk = {
            "key": key,
            "signature": signature,
            "timestamp": time.time()
        }

    @changes
    def __generateOTPKs(self, num_otpks = None):
        """
        Generate the given amount of OTPKs.
        If the value of num_otpks is None, set it to the max_num_otpks value of the configuration.
        """

        if num_otpks == None:
            num_otpks = self.__config.max_num_otpks
        
        otpks = []

        for _ in range(num_otpks):
            otpks.append(self.__KeyQuad.generate())

        try:
            self.__otpks.extend(otpks)
        except AttributeError:
            self.__otpks = otpks

    def __checkSPKTimestamp(self):
        """
        Check whether the SPK is too old and generate a new one in that case.
        """

        if time.time() - self.__spk["timestamp"] > self.__config.spk_timeout:
            self.__generateSPK()

    def __refillOTPKs(self):
        """
        If the amount of available OTPKs fell under the minimum, refills the OTPKs up to the maximum limit again.
        """

        if len(self.__otpks) < self.__config.min_num_otpks:
            self.__generateOTPKs(self.__config.max_num_otpks - len(self.__otpks))

    def getPublicBundle(self):
        """
        Fill a PublicBundle object with the public bundle data of this State.
        """

        ik_enc = self.__ik.enc
        spk_enc = self.__spk["key"].enc
        spk_sig = self.__spk["signature"]
        otpk_encs = [ otpk.enc for otpk in self.__otpks ]

        return PublicBundle(ik_enc, spk_enc, spk_sig, otpk_encs)

    @changes
    def hideFromPublicBundle(self, otpk_enc):
        """
        Hide a one-time pre key from the public bundle.
        """
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
        for otpk in self.__otpks:
            if otpk.enc == otpk_enc:
                return self.__otpks.remove(otpk)

        for otpk in self.__hidden_otpks:
            if otpk.enc == otpk_enc:
                return self.__hidden_otpks.remove(otpk)

        self.__refillOTPKs()

    def initSessionActive(self, other_public_bundle, allow_zero_otpks = False):
        other_ik = self.__KeyQuad(encryption_key = other_public_bundle.ik)

        other_spk = {
            "key": self.__KeyQuad(encryption_key = other_public_bundle.spk),
            "signature": other_public_bundle.spk_signature
        }

        other_otpks = [ self.__KeyQuad(encryption_key = otpk) for otpk in other_public_bundle.otpks ]

        if len(other_otpks) == 0 and not allow_zero_otpks:
            raise SessionInitiationException("The other public bundle does not contain any OTPKs, which is not allowed")

        other_spk_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(other_spk["key"].enc, self.__config.curve)

        if not self.__XEdDSA(encryption_key = other_ik.enc).verify(other_spk_serialized, other_spk["signature"]):
            raise SessionInitiationException("The signature of this public bundle's spk could not be verifified!")

        ek = self.__KeyQuad.generate()

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

        ik_enc_serialized       = self.__EncryptionKeyEncoder.encodeEncryptionKey(self.__ik.enc, self.__config.curve)
        other_ik_enc_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(other_ik.enc,  self.__config.curve)

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

    def initSessionPassive(self, session_init_data, allow_no_otpk = False, keep_otpk = False):
        """
        The specification of X3DH dictates to delete the one time pre keys as soon as they are used.
        This behaviour provides security but may lead to considerable usability downsides in some environments.
        For that reason the keep_otpk flag exists. If set to True, the one time pre key is not automatically deleted.
        USE WITH CARE, THIS MAY INTRODUCE SECURITY LEAKS IF USED INCORRECTLY.
        If you decide set the flag and to keep the otpks, you have to manage deleting them yourself, e.g. by subclassing this class and overriding this method.
        """

        other_ik = self.__KeyQuad(encryption_key = session_init_data["ik"])
        other_ek = self.__KeyQuad(encryption_key = session_init_data["ek"])

        if self.__spk["key"].enc != session_init_data["spk"]:
            raise SessionInitiationException("The SPK used for this session initialization has been rotated, the session can not be initiated")

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
                raise SessionInitiationException("The OTPK used for this session initialization has been deleted, the session can not be initiated")
        elif not allow_no_otpk:
            raise SessionInitiationException("This session initialization data does not contain an OTPK, which is not allowed")

        dh1 = self.__spk["key"].getSharedSecret(other_ik)
        dh2 = self.__ik.getSharedSecret(other_ek)
        dh3 = self.__spk["key"].getSharedSecret(other_ek)
        dh4 = b""
        
        if my_otpk:
            dh4 = my_otpk.getSharedSecret(other_ek)

        sk = self.__kdf(dh1 + dh2 + dh3 + dh4)

        other_ik_enc_serialized = self.__EncryptionKeyEncoder.encodeEncryptionKey(other_ik.enc,  self.__config.curve)
        ik_enc_serialized       = self.__EncryptionKeyEncoder.encodeEncryptionKey(self.__ik.enc, self.__config.curve)

        ad = other_ik_enc_serialized + ik_enc_serialized

        if my_otpk and not keep_otpk:
            self.deleteOTPK(my_otpk.enc)

        return {
            "ad": ad,
            "sk": sk
        }

    @property
    def spk(self):
        return self.__spk["key"]

    @property
    def spk_signature(self):
        return self.__spk["signature"]

    @property
    def ik(self):
        return self.__ik

    @property
    def otpks(self):
        return self.__otpks

    @property
    def hidden_otpks(self):
        return self.__hidden_otpks

    @property
    def changed(self):
        """
        Read, whether this State has changed since it was loaded/since this flag was last cleared.
        Clears the flag when reading.
        """

        changed = self._changed
        self._changed = False
        return changed
