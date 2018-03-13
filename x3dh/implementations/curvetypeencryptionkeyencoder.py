from __future__ import absolute_import

from ..encryptionkeyencoder import EncryptionKeyEncoder

class CurveTypeEncryptionKeyEncoder(EncryptionKeyEncoder):
    @staticmethod
    def encodeEncryptionKey(encryption_key, encryption_key_type):
        if encryption_key_type == "25519":
            return b'\x05' + encryption_key
