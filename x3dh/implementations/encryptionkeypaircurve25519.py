from __future__ import absolute_import

import base64

from ..encryptionkeypair import EncryptionKeyPair

from ..exceptions import MissingKeyException

from nacl.bindings import crypto_box_NONCEBYTES
from nacl.bindings.crypto_scalarmult import crypto_scalarmult

from nacl.public import Box
from nacl.public import PrivateKey as Curve25519DecryptionKey
from nacl.public import PublicKey  as Curve25519EncryptionKey

from nacl.utils import random

from xeddsa.implementations import XEdDSA25519

class EncryptionKeyPairCurve25519(EncryptionKeyPair):
    def __init__(self, enc = None, dec = None):
        wrap = self.__class__.__wrap

        self.__enc = wrap(enc, Curve25519EncryptionKey)
        self.__dec = wrap(dec, Curve25519DecryptionKey)

        if self.__dec and not self.__enc:
            self.__enc = self.__dec.public_key

    @staticmethod
    def __wrap(key, cls):
        if not key:
            return None

        if isinstance(key, cls):
            return key

        return cls(key)

    @classmethod
    def generate(cls):
        return cls(dec = XEdDSA25519.generate_mont_priv())

    def serialize(self):
        enc = self.enc
        dec = self.dec

        return {
            "super" : super(EncryptionKeyPairCurve25519, self).serialize(),
            "enc"   : None if enc == None else base64.b64encode(enc).decode("US-ASCII"),
            "dec"   : None if dec == None else base64.b64encode(dec).decode("US-ASCII")
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        self = super(EncryptionKeyPairCurve25519, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        enc = serialized["enc"]
        dec = serialized["dec"]

        self.__enc = None if enc == None else base64.b64decode(enc.encode("US-ASCII"))
        self.__dec = None if dec == None else base64.b64decode(dec.encode("US-ASCII"))

        return self

    @property
    def enc(self):
        return None if self.__enc == None else bytes(self.__enc)

    @property
    def dec(self):
        return None if self.__dec == None else bytes(self.__dec)

    def encrypt(self, data, other):
        return bytes(self.__getBox(other).encrypt(data, random(crypto_box_NONCEBYTES)))

    def decrypt(self, data, other):
        return bytes(self.__getBox(other).decrypt(data))

    def __getBox(self, other):
        if not self.__dec:
            raise MissingKeyException(
                "Cannot get a shared secret using this EncryptionKeyPairCurve25519, " +
                "decryption key missing."
            )

        if not other.__enc:
            raise MissingKeyException(
                "Cannot get a shared secret using the other " +
                "EncryptionKeyPairCurve25519, encryption key missing."
            )

        return Box(self.__dec, other.__enc)

    def getSharedSecret(self, other):
        if not self.__dec:
            raise MissingKeyException(
                "Cannot get a shared secret using this EncryptionKeyPairCurve25519, " +
                "decryption key missing."
            )

        if not other.__enc:
            raise MissingKeyException(
                "Cannot get a shared secret using the other " +
                "EncryptionKeyPairCurve25519, encryption key missing"
            )

        return crypto_scalarmult(
            self.dec,
            other.enc
        )
