from typing_extensions import assert_never

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto_provider import CryptoProvider, HashFunction


__all__ = [  # pylint: disable=unused-variable
    "CryptoProviderImpl"
]


def get_hash_algorithm(hash_function: HashFunction) -> hashes.HashAlgorithm:
    """
    Args:
        hash_function: Identifier of a hash function.

    Returns:
        The implementation of the hash function as a cryptography
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` object.
    """

    if hash_function is HashFunction.SHA_256:
        return hashes.SHA256()
    if hash_function is HashFunction.SHA_512:
        return hashes.SHA512()

    return assert_never(hash_function)


class CryptoProviderImpl(CryptoProvider):
    """
    Cryptography provider based on the Python package `cryptography <https://github.com/pyca/cryptography>`_.
    """

    @staticmethod
    async def hkdf_derive(
        hash_function: HashFunction,
        length: int,
        salt: bytes,
        info: bytes,
        key_material: bytes
    ) -> bytes:
        return HKDF(
            algorithm=get_hash_algorithm(hash_function),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(key_material)
