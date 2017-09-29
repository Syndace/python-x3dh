import base64

from KeyQuad import KeyQuad
from X3DHException import X3DHException

from nacl.exceptions import BadSignatureError
from nacl.public import Box
from nacl.public import PrivateKey as Curve25519SecretKey
from nacl.public import PublicKey as Curve25519PublicKey
from nacl.signing import SigningKey as Ed25519SigningKey
from nacl.signing import VerifyKey as Ed25519VerifyingKey

class KeyQuad25519(KeyQuad):
    def __init__(self, public_key = None, secret_key = None, signing_key = None, verifying_key = None):
        self.__public_key = KeyQuad25519.__wrap(public_key, Curve25519PublicKey)
        self.__secret_key = KeyQuad25519.__wrap(secret_key, Curve25519SecretKey)
        self.__signing_key = KeyQuad25519.__wrap(signing_key, Ed25519SigningKey)
        self.__verifying_key = KeyQuad25519.__wrap(verifying_key, Ed25519VerifyingKey)

        if self.__signing_key and not self.__verifying_key:
            # Derive the verifying key from the signing key
            self.__verifying_key = self.__signing_key.verify_key

        if self.__signing_key and not self.__secret_key:
            # Derive the secret_key key from the signing key
            self.__secret_key = self.__signing_key.to_curve25519_private_key()

        if self.__verifying_key and not self.__public_key:
            # Derive the public key from the verifying key
            self.__public_key = self.__verifying_key.to_curve25519_public_key()

        if self.__secret_key and not self.__public_key:
            # Derive the public key from the secret key
            self.__public_key = secret_key.public_key

    @staticmethod
    def __wrap(key, cls):
        if not key:
            return None

        if isinstance(key, cls):
            return key

        return cls(key)

    @classmethod
    def generate(cls):
        return cls(signing_key = Ed25519SigningKey.generate())

    @classmethod
    def fromSerializable(cls, data):
        public_key = data.get("pub")
        secret_key = data.get("sec")
        signing_key = data.get("sig")
        verifying_key = data.get("ver")

        if public_key:
            public_key = base64.b64decode(public_key)
        if secret_key:
            secret_key = base64.b64decode(secret_key)
        if signing_key:
            signing_key = base64.b64decode(signing_key)
        if verifying_key:
            verifying_key = base64.b64decode(verifying_key)

        return cls(public_key, secret_key, signing_key, verifying_key)

    def toSerializable(self):
        data = {}

        # Add the signing key, if it exists
        if self.__signing_key:
            data["sig"] = base64.b64encode(self.sig)

        # If there is no signing key, add the secret key if it exists
        if (not "sig" in data) and self.__secret_key:
            data["sec"] = base64.b64encode(self.sec)

        # If there is no signing key, add the verifying key if it exists
        if (not "sig" in data) and self.__verifying_key:
            data["ver"] = base64.b64encode(self.ver)

        # If there is neither a verifying key nor a secret key nor a signing key, add the public key, if it exists
        if (not "ver" in data) and (not "sec" in data) and (not "sig" in data) and self.__public_key:
            data["pub"] = base64.b64encode(self.pub)

        return data

    @property
    def pub(self):
        return bytes(self.__public_key)

    @property
    def sec(self):
        return bytes(self.__secret_key)

    @property
    def sig(self):
        return bytes(self.__signing_key)

    @property
    def ver(self):
        return bytes(self.__verifying_key)

    def sign(self, data):
        if not self.__signing_key:
            raise X3DHException("Cannot sign using this key quad, signing key missing")

        return bytes(self.__signing_key.sign(data).signature)

    def verify(self, data, signature):
        if not self.__verifying_key:
            raise X3DHException("Cannot verify using this key quad, verifying key missing")

        try:
            self.__verifying_key.verify(data, signature)
            return True
        except BadSignatureError:
            return False

    def getSharedSecret(self, other):
        if not self.__signing_key:
            raise X3DHException("Cannot get a shared secret using this key quad, secret key missing")

        if not other.__public_key:
            raise X3DHException("Cannot get a shared secret using the other key quad, public key missing")

        return bytes(Box(self.__secret_key, other.__public_key))
