from ctypes import CDLL
from typing import Tuple

nacl: CDLL

class CryptError(Exception):
    ...

crypto_box_PUBLICKEYBYTES: int
crypto_box_SECRETKEYBYTES: int
crypto_scalarmult_BYTES: int

Curve25519PrivateKey = bytes
Curve25519PublicKey  = bytes

Ed25519PrivateKey = bytes
Ed25519PublicKey  = bytes
Ed25519Signature  = bytes

def crypto_box_keypair()  -> Tuple[Curve25519PublicKey, Curve25519PrivateKey]: ...
def crypto_sign_keypair() -> Tuple[Ed25519PublicKey, Ed25519PrivateKey]: ...
def crypto_sign_detached(msg: bytes, sk: Ed25519PrivateKey) -> Ed25519Signature: ...
def crypto_sign_verify_detached(sig: Ed25519Signature, msg: bytes, vk: Ed25519PublicKey) -> bytes: ...

def crypto_sign_ed25519_pk_to_curve25519(pk: Ed25519PublicKey) -> Curve25519PublicKey: ...
def crypto_sign_ed25519_sk_to_curve25519(sk: Ed25519PrivateKey) -> Curve25519PrivateKey: ...
