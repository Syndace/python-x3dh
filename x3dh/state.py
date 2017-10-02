from __future__ import absolute_import

import base64
from functools import wraps
import os
import time

from .config import Config
from .jsonutils import dumpToFile, loadFromFile
from .publicbundle import PublicBundle
from .exceptions import SessionInitiationException

from scci.implementations import KeyQuad25519, KeyQuad448

from hkdf import hkdf_expand, hkdf_extract

def changes(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        args[0]._changed = True
        return f(*args, **kwargs)
    return wrapper

class State(object):
    def __init__(self, directory, configuration = None):
        """
        directory: A path to a directory where this State object may save/load data to/from.
        configuration: If present, use this as the configuration for this State object. Otherwise, use the configuration previously saved.
        """

        # Track whether this State has somehow changed since loading it
        # This can be used e.g. to republish the public bundle if something has changed
        self._changed = False

        self.__directory = directory

        # Load the configuration
        self.__config = configuration if configuration else Config.fromFile(os.path.join(self.__directory, "configuration.json"))

        if self.__config.curve == "X25519":
            self.__KeyQuad = KeyQuad25519
        if self.__config.curve == "X448":
            self.__KeyQuad = KeyQuad448

        self.__loadState()

    def __loadState(self):
        ik = loadFromFile(os.path.join(self.__directory, "ik.json"), self.__generateIK, True)
        if ik:
            self.__ik = self.__KeyQuad.fromSerializable(ik)

        spk = loadFromFile(os.path.join(self.__directory, "spk.json"), self.__generateSPK, True)
        if spk:
            self.__spk = {
                "key": self.__KeyQuad.fromSerializable(spk["key"]),
                "signature": base64.b64decode(spk["signature"]),
                "timestamp": spk["timestamp"]
            }

        otpks = loadFromFile(os.path.join(self.__directory, "otpks.json"), self.__generateOTPKs, True)
        if otpks:
            self.__otpks = [ self.__KeyQuad.fromSerializable(otpk) for otpk in otpks ]

        self.__checkSPKTimestamp()
        self.__refillOTPKs()

    def __kdf(self, secret_key_material):
        salt = b"\x00" * self.__config.hash_function().digest_size

        if self.__config.curve == "X25519":
            input_key_material = b"\xFF" * 32
        if self.__config.curve == "X448":
            input_key_material = b"\xFF" * 57

        input_key_material += secret_key_material

        return hkdf_expand(hkdf_extract(salt, input_key_material, self.__config.hash_function), self.__config.info_string, 32, self.__config.hash_function)

    @changes
    def __generateIK(self):
        """
        Generate an IK. This should only be done once.
        """

        self.__ik = self.__KeyQuad.generate()
    
    @changes
    def __generateSPK(self):
        """
        Generate a new PK and sign its public key using the IK, add the timestamp aswell to allow for periodic rotations.
        """

        key = self.__KeyQuad.generate()
        signature = self.__ik.sign(key.pub)

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

        ik_ver = self.__ik.ver
        spk_pub = self.__spk["key"].pub
        spk_sig = self.__spk["signature"]
        otpk_pubs = [ otpk.pub for otpk in self.__otpks ]

        return PublicBundle(ik_ver, spk_pub, spk_sig, otpk_pubs)

    def initSessionActive(self, other_public_bundle, allow_zero_otpks = False):
        other_ik = self.__KeyQuad(verifying_key = other_public_bundle.ik)

        other_spk = {
            "key": self.__KeyQuad(public_key = other_public_bundle.spk),
            "signature": other_public_bundle.spk_signature
        }

        other_otpks = [ self.__KeyQuad(public_key = otpk) for otpk in other_public_bundle.otpks ]

        if len(other_otpks) == 0 and not allow_zero_otpks:
            raise SessionInitiationException("The other public bundle does not contain any OTPKs, which is not allowed")

        if not other_ik.verify(other_spk["key"].pub, other_spk["signature"]):
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

        ad = self.__ik.ver + other_ik.ver

        return {
            "to_other": {
                "ik": self.__ik.ver,
                "ek": ek.pub,
                "otpk": otpk.pub if otpk else None,
                "spk": other_spk["key"].pub
            },
            "ad": ad,
            "sk": sk
        }

    def initSessionPassive(self, session_init_data, allow_no_otpk = False):
        other_ik = self.__KeyQuad(verifying_key = session_init_data["ik"])
        other_ek = self.__KeyQuad(public_key = session_init_data["ek"])

        if self.__spk["key"].pub != session_init_data["spk"]:
            raise SessionInitiationException("The SPK used for this session initialization has been rotated, the session can not be initiated")

        my_otpk = None
        if "otpk" in session_init_data:
            for otpk in self.__otpks:
                if otpk.pub == session_init_data["otpk"]:
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

        ad = other_ik.ver + self.__ik.ver

        if my_otpk:
            self.__otpks.remove(my_otpk)
            self.__refillOTPKs()

        return {
            "ad": ad,
            "sk": sk
        }

    def shutdown(self):
        """
        Save configuration and state to files in the directory provided to __init__.
        """

        self.__config.toFile(os.path.join(self.__directory, "configuration.json"))

        dumpToFile(os.path.join(self.__directory, "ik.json"), self.__ik.toSerializable())

        dumpToFile(os.path.join(self.__directory, "spk.json"), {
            "key": self.__spk["key"].toSerializable(),
            "signature": base64.b64encode(self.__spk["signature"]),
            "timestamp": self.__spk["timestamp"]
        })

        dumpToFile(os.path.join(self.__directory, "otpks.json"), [ otpk.toSerializable() for otpk in self.__otpks ])

    @property
    def changed(self):
        """
        Read, whether this State has changed since it was loaded/since this flag was last cleared.
        Clears the flag when reading.
        """

        changed = self._changed
        self._changed = False
        return changed
