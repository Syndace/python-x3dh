from abc import ABC, abstractmethod
import enum
from typing_extensions import assert_never


__all__ = [  # pylint: disable=unused-variable
    "CryptoProvider",
    "HashFunction"
]


@enum.unique
class HashFunction(enum.Enum):
    """
    Enumeration of the hash functions supported for the key derivation step of X3DH.
    """

    SHA_256: str = "SHA_256"
    SHA_512: str = "SHA_512"

    @property
    def hash_size(self) -> int:
        """
        Returns:
            The byte size of the hashes produced by this hash function.
        """

        if self is HashFunction.SHA_256:
            return 32
        if self is HashFunction.SHA_512:
            return 64

        return assert_never(self)


class CryptoProvider(ABC):
    """
    Abstraction of the cryptographic operations needed by this package to allow for different backend
    implementations.
    """

    @staticmethod
    @abstractmethod
    async def hkdf_derive(
        hash_function: HashFunction,
        length: int,
        salt: bytes,
        info: bytes,
        key_material: bytes
    ) -> bytes:
        """
        Args:
            hash_function: The hash function to parameterize the HKDF with.
            length: The number of bytes to derive.
            salt: The salt input for the HKDF.
            info: The info input for the HKDF.
            key_material: The input key material to derive from.

        Returns:
            The derived key material.
        """
