from __future__ import absolute_import

import base64

from ..exceptions import MissingKeyException
from ..keypair import KeyPair

from nacl.bindings import crypto_box_NONCEBYTES
from nacl.bindings.crypto_scalarmult import crypto_scalarmult

from nacl.public import Box
from nacl.public import PrivateKey as Curve25519DecryptionKey
from nacl.public import PublicKey  as Curve25519EncryptionKey

from nacl.utils import random

from xeddsa.implementations import XEdDSA25519

class KeyPairCurve25519(KeyPair):
    """
    An implementation of the KeyPair interface for Montgomery Curve25519 key pairs.
    """

    def __init__(self, priv = None, pub = None):
        wrap = self.__class__.__wrap

        self.__priv = wrap(priv, Curve25519DecryptionKey)
        self.__pub  = wrap(pub,  Curve25519EncryptionKey)

        if self.__priv != None and self.__pub == None:
            self.__pub = self.__priv.public_key

    @classmethod
    def generate(cls):
        return cls(priv = XEdDSA25519.generate_mont_priv())

    @staticmethod
    def __wrap(key, cls):
        if key == None:
            return None

        if isinstance(key, cls):
            return key

        return cls(key)

    def serialize(self):
        priv = self.priv
        pub  = self.pub

        return {
            "super" : super(KeyPairCurve25519, self).serialize(),
            "priv"  : None if priv == None else base64.b64encode(priv).decode("US-ASCII"),
            "pub"   : None if pub  == None else base64.b64encode(pub).decode("US-ASCII")
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        wrap = cls.__wrap

        self = super(KeyPairCurve25519, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )

        priv = serialized["priv"]
        pub  = serialized["pub"]

        priv = None if priv == None else base64.b64decode(priv.encode("US-ASCII"))
        pub  = None if pub  == None else base64.b64decode(pub.encode("US-ASCII"))

        self.__priv = wrap(priv, Curve25519DecryptionKey)
        self.__pub  = wrap(pub,  Curve25519EncryptionKey)

        return self

    @property
    def priv(self):
        return None if self.__priv == None else bytes(self.__priv)

    @property
    def pub(self):
        return None if self.__pub == None else bytes(self.__pub)

    def encrypt(self, data, other):
        return bytes(self.__getBox(other).encrypt(data, random(crypto_box_NONCEBYTES)))

    def decrypt(self, data, other):
        return bytes(self.__getBox(other).decrypt(data))

    def __getBox(self, other):
        if self.__priv == None:
            raise MissingKeyException(
                "Cannot get a shared secret using this KeyPairCurve25519, private key " +
                "missing."
            )

        if other.__pub == None:
            raise MissingKeyException(
                "Cannot get a shared secret using the other KeyPairCurve25519, public " +
                "key missing."
            )

        return Box(self.__priv, other.__pub)

    def getSharedSecret(self, other):
        if self.__priv == None:
            raise MissingKeyException(
                "Cannot get a shared secret using this KeyPairCurve25519, private key " +
                "missing."
            )

        if other.__pub == None:
            raise MissingKeyException(
                "Cannot get a shared secret using the other KeyPairCurve25519, public " +
                "key missing."
            )

        return crypto_scalarmult(
            self.priv,
            other.pub
        )
