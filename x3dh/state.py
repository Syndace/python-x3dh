from __future__ import absolute_import

import base64
from functools import wraps
import os
import time

from .exceptions import KeyExchangeException
from .implementations import KeyPairCurve25519
from .publicbundle import PublicBundle
from .serializable import Serializable

from xeddsa.implementations import XEdDSA25519

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def changes(f):
    @wraps(f)
    def _changes(*args, **kwargs):
        args[0]._changed = True
        return f(*args, **kwargs)
    return _changes

class State(Serializable):
    """
    The state is the core of the X3DH protocol. It manages a collection of key pairs and
    signatures and offers methods to do key exchanges with other parties.
    """

    CRYPTOGRAPHY_BACKEND = default_backend()

    HASH_FUNCTIONS = {
        "SHA-256": hashes.SHA256,
        "SHA-512": hashes.SHA512
    }

    def __init__(
        self,
        info_string,
        curve,
        hash_function,
        spk_timeout,
        min_num_otpks,
        max_num_otpks,
        public_key_encoder_class
    ):
        """
        Prepare an X3DH state to provide asynchronous key exchange using a set of public
        keys called "public bundle".

        :param info_string: A bytes-like object encoding a string unique to this usage
            within the application.
        :param curve: The type of the curve. Allowed values: (the string) "25519"
            ("448" might follow soon).
        :param hash_function: The hash function to use. Allowed values: (the strings)
            "SHA-256" and "SHA-512".
        :param spk_timeout: Rotate the SPK after this amount of time in seconds.
        :param min_num_otpks: Minimum number of OTPKs that must always be available.
        :param max_num_otpks: Maximum number of OTPKs that may be available.
        :param public_key_encoder_class: A sub class of PublicKeyEncoder.
        """

        if not isinstance(info_string, bytes):
            raise TypeError("Wrong type passed for the info_string parameter.")

        if not curve in [ "25519" ]:
            raise ValueError("Invalid value passed for the curve parameter.")

        if not hash_function in State.HASH_FUNCTIONS:
            raise ValueError("Invalid value passed for the hash_function parameter.")

        self.__info_string      = info_string
        self.__curve            = curve
        self.__hash_function    = State.HASH_FUNCTIONS[hash_function]
        self.__spk_timeout      = spk_timeout
        self.__min_num_otpks    = min_num_otpks
        self.__max_num_otpks    = max_num_otpks
        self.__PublicKeyEncoder = public_key_encoder_class

        # Load the configuration
        if self.__curve == "25519":
            self.__KeyPair = KeyPairCurve25519
            self.__XEdDSA  = XEdDSA25519

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
        spk = {
            "key"       : self.__spk["key"].serialize(),
            "signature" : base64.b64encode(self.__spk["signature"]).decode("US-ASCII"),
            "timestamp" : self.__spk["timestamp"]
        }

        return {
            "changed"      : self._changed,
            "ik"           : self.__ik.serialize(),
            "spk"          : spk,
            "otpks"        : [ otpk.serialize() for otpk in self.__otpks ],
            "hidden_otpks" : [ otpk.serialize() for otpk in self.__hidden_otpks ]
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = cls(*args, **kwargs)

        parseKeyPair = self.__KeyPair.fromSerialized

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

        self.__ik = self.__KeyPair.generate()
    
    @changes
    def __generateSPK(self):
        """
        Generate a new PK and sign its public key using the IK, add the timestamp aswell
        to allow for periodic rotations.
        """

        key = self.__KeyPair.generate()

        key_serialized = self.__PublicKeyEncoder.encodePublicKey(
            key.pub,
            self.__curve
        )

        signature = self.__XEdDSA(mont_priv = self.__ik.priv).sign(key_serialized)

        self.__spk = {
            "key": key,
            "signature": signature,
            "timestamp": time.time()
        }

    @changes
    def __generateOTPKs(self, num_otpks = None):
        """
        Generate the given amount of OTPKs.

        :param num_otpks: Either an integer or None.

        If the value of num_otpks is None, set it to the max_num_otpks value of the
        configuration.
        """

        if num_otpks == None:
            num_otpks = self.__max_num_otpks
        
        otpks = []

        for _ in range(num_otpks):
            otpks.append(self.__KeyPair.generate())

        try:
            self.__otpks.extend(otpks)
        except AttributeError:
            self.__otpks = otpks

    ####################
    # internal helpers #
    ####################

    def __kdf(self, secret_key_material):
        """
        :param secret_key_material: A bytes-like object encoding the secret key material.
        :returns: A bytes-like object encoding the shared secret key.
        """

        salt = b"\x00" * self.__hash_function().digest_size

        if self.__curve == "25519":
            input_key_material = b"\xFF" * 32
        if self.__curve == "448":
            input_key_material = b"\xFF" * 57

        input_key_material += secret_key_material

        hkdf = HKDF(
            algorithm=self.__hash_function(),
            length=32,
            salt=salt,
            info=self.__info_string,
            backend=self.__class__.CRYPTOGRAPHY_BACKEND
        )

        return hkdf.derive(input_key_material)

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
    def hideFromPublicBundle(self, otpk_pub):
        """
        Hide a one-time pre key from the public bundle.

        :param otpk_pub: The public key of the one-time pre key to hide, encoded as a
            bytes-like object.
        """

        self.__checkSPKTimestamp()

        for otpk in self.__otpks:
            if otpk.pub == otpk_pub:
                self.__otpks.remove(otpk)
                self.__hidden_otpks.append(otpk)
                self.__refillOTPKs()

    @changes
    def deleteOTPK(self, otpk_pub):
        """
        Delete a one-time pre key, either publicly visible or hidden.

        :param otpk_pub: The public key of the one-time pre key to delete, encoded as a
            bytes-like object.
        """

        self.__checkSPKTimestamp()

        for otpk in self.__otpks:
            if otpk.pub == otpk_pub:
                self.__otpks.remove(otpk)

        for otpk in self.__hidden_otpks:
            if otpk.pub == otpk_pub:
                self.__hidden_otpks.remove(otpk)

        self.__refillOTPKs()

    ############################
    # public bundle management #
    ############################

    def getPublicBundle(self):
        """
        Fill a PublicBundle object with the public bundle data of this State.

        :returns: An instance of PublicBundle, filled with the public data of this State.
        """

        self.__checkSPKTimestamp()

        ik_pub    = self.__ik.pub
        spk_pub   = self.__spk["key"].pub
        spk_sig   = self.__spk["signature"]
        otpk_pubs = [ otpk.pub for otpk in self.__otpks ]

        return PublicBundle(ik_pub, spk_pub, spk_sig, otpk_pubs)

    @property
    def changed(self):
        """
        Read, whether this State has changed since it was loaded/since this flag was last
        cleared.

        :returns: A boolean indicating, whether the public bundle data has changed since
            last reading this flag.

        Clears the flag when reading.
        """

        self.__checkSPKTimestamp()

        changed = self._changed
        self._changed = False
        return changed

    ################
    # key exchange #
    ################

    def getSharedSecretActive(
        self,
        other_public_bundle,
        allow_zero_otpks = False
    ):
        """
        Do the key exchange, as the active party. This involves selecting keys from the
        passive parties' public bundle.

        :param other_public_bundle: An instance of PublicBundle, filled with the public
            data of the passive party.
        :param allow_zero_otpks: A flag indicating whether bundles with no one-time pre
            keys are allowed or throw an error. False is the recommended default.
        :returns: A dictionary containing the shared secret, the shared associated data
            and the data the passive party needs to finalize the key exchange.

        The returned structure looks like this::
        
            {
                "to_other": {
                    # The public key of the active parties' identity key pair
                    "ik": bytes,

                    # The public key of the active parties' ephemeral key pair
                    "ek": bytes,

                    # The public key of the used passive parties' one-time pre key or None
                    "otpk": bytes or None,

                    # The public key of the passive parties' signed pre key pair
                    "spk": bytes
                },
                "ad": bytes, # The shared associated data
                "sk": bytes  # The shared secret
            }

        :raises KeyExchangeException: If an error occurs during the key exchange. The
            exception message will contain (human-readable) details.
        """

        self.__checkSPKTimestamp()

        other_ik = self.__KeyPair(pub = other_public_bundle.ik)

        other_spk = {
            "key": self.__KeyPair(pub = other_public_bundle.spk),
            "signature": other_public_bundle.spk_signature
        }

        other_otpks = [
            self.__KeyPair(pub = otpk) for otpk in other_public_bundle.otpks
        ]

        if len(other_otpks) == 0 and not allow_zero_otpks:
            raise KeyExchangeException(
                "The other public bundle does not contain any OTPKs, which is not " +
                "allowed."
            )

        other_spk_serialized = self.__PublicKeyEncoder.encodePublicKey(
            other_spk["key"].pub,
            self.__curve
        )

        if not self.__XEdDSA(mont_pub = other_ik.pub).verify(
            other_spk_serialized,
            other_spk["signature"]
        ):
            raise KeyExchangeException(
                "The signature of this public bundle's spk could not be verifified."
            )

        ek = self.__KeyPair.generate()

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

        ik_pub_serialized = self.__PublicKeyEncoder.encodePublicKey(
            self.__ik.pub,
            self.__curve
        )

        other_ik_pub_serialized = self.__PublicKeyEncoder.encodePublicKey(
            other_ik.pub,
            self.__curve
        )

        ad = ik_pub_serialized + other_ik_pub_serialized

        return {
            "to_other": {
                "ik": self.__ik.pub,
                "ek": ek.pub,
                "otpk": otpk.pub if otpk else None,
                "spk": other_spk["key"].pub
            },
            "ad": ad,
            "sk": sk
        }

    def getSharedSecretPassive(
        self,
        passive_exchange_data,
        allow_no_otpk = False,
        keep_otpk = False
    ):
        """
        Do the key exchange, as the passive party. This involves retrieving data about the
        key exchange from the active party.

        :param passive_exchange_data: A structure generated by the active party, which
            contains data requried to complete the key exchange. See the "to_other" part
            of the structure returned by "getSharedSecretActive".
        :param allow_no_otpk: A boolean indicating whether to allow key exchange, even if
            the active party did not use a one-time pre key. The recommended default is
            False.
        :param keep_otpk: Keep the one-time pre key after using it, instead of deleting
            it. See the notes below.
        :returns: A dictionary containing the shared secret and the shared associated
            data.

        The returned structure looks like this::
        
            {
                "ad": bytes, # The shared associated data
                "sk": bytes  # The shared secret
            }

        The specification of X3DH dictates to delete one-time pre keys as soon as they are
        used.

        This behaviour provides security but may lead to considerable usability downsides
        in some environments.

        For that reason the keep_otpk flag exists.
        If set to True, the one-time pre key is not automatically deleted.
        USE WITH CARE, THIS MAY INTRODUCE SECURITY LEAKS IF USED INCORRECTLY.
        If you decide to set the flag and to keep the otpks, you have to manage deleting
        them yourself, e.g. by subclassing this class and overriding this method.

        :raises KeyExchangeException: If an error occurs during the key exchange. The
            exception message will contain (human-readable) details.
        """

        self.__checkSPKTimestamp()

        other_ik = self.__KeyPair(pub = passive_exchange_data["ik"])
        other_ek = self.__KeyPair(pub = passive_exchange_data["ek"])

        if self.__spk["key"].pub != passive_exchange_data["spk"]:
            raise KeyExchangeException(
                "The SPK used for this key exchange has been rotated, the key exchange " +
                "can not be completed."
            )

        my_otpk = None
        if "otpk" in passive_exchange_data:
            for otpk in self.__otpks:
                if otpk.pub == passive_exchange_data["otpk"]:
                    my_otpk = otpk
                    break

            for otpk in self.__hidden_otpks:
                if otpk.pub == passive_exchange_data["otpk"]:
                    my_otpk = otpk
                    break

            if not my_otpk:
                raise KeyExchangeException(
                    "The OTPK used for this key exchange has been deleted, the key " +
                    "exchange can not be completed."
                )
        elif not allow_no_otpk:
            raise KeyExchangeException(
                "This key exchange data does not contain an OTPK, which is not allowed."
            )

        dh1 = self.__spk["key"].getSharedSecret(other_ik)
        dh2 = self.__ik.getSharedSecret(other_ek)
        dh3 = self.__spk["key"].getSharedSecret(other_ek)
        dh4 = b""
        
        if my_otpk:
            dh4 = my_otpk.getSharedSecret(other_ek)

        sk = self.__kdf(dh1 + dh2 + dh3 + dh4)

        other_ik_pub_serialized = self.__PublicKeyEncoder.encodePublicKey(
            other_ik.pub,
            self.__curve
        )

        ik_pub_serialized = self.__PublicKeyEncoder.encodePublicKey(
            self.__ik.pub,
            self.__curve
        )

        ad = other_ik_pub_serialized + ik_pub_serialized

        if my_otpk and not keep_otpk:
            self.deleteOTPK(my_otpk.pub)

        return {
            "ad": ad,
            "sk": sk
        }

    @property
    def spk(self):
        """
        :returns: The signed pre key pair as an instance of KeyPair.
        """

        self.__checkSPKTimestamp()

        return self.__spk["key"]

    @property
    def spk_signature(self):
        """
        :returns: The signature that was created using the identity key to sign the
            encoded public key of the signed pre key pair. The signature is encoded as a
            bytes-like object.
        """

        self.__checkSPKTimestamp()

        return self.__spk["signature"]

    @property
    def ik(self):
        """
        :returns: The identity key pair as an instance of KeyPair.
        """

        self.__checkSPKTimestamp()

        return self.__ik

    @property
    def otpks(self):
        """
        :returns: A list of all public one-time pre keys, as instances of KeyPair.
        """

        self.__checkSPKTimestamp()

        return self.__otpks

    @property
    def hidden_otpks(self):
        """
        :returns: A list of all hidden one-time pre keys, as instances of KeyPair.
        """

        self.__checkSPKTimestamp()

        return self.__hidden_otpks
