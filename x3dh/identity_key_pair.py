# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from abc import ABC, abstractmethod
import json
from typing import cast
from typing_extensions import assert_never

import xeddsa

from .migrations import parse_identity_key_pair_model
from .models import IdentityKeyPairModel
from .types import JSONObject, SecretType


__all__ = [  # pylint: disable=unused-variable
    "IdentityKeyPair",
    "IdentityKeyPairPriv",
    "IdentityKeyPairSeed"
]


class IdentityKeyPair(ABC):
    """
    An identity key pair.

    There are following requirements for the identity key pair:

    * It must be able to create and verify Ed25519-compatible signatures.
    * It must be able to perform X25519-compatible Diffie-Hellman key agreements.

    There are at least two different kinds of key pairs that can fulfill these requirements: Ed25519 key pairs
    and Curve25519 key pairs. The birational equivalence of both curves can be used to "convert" one pair to
    the other.

    Both types of key pairs share the same private key, however instead of a private key, a seed can be used
    which the private key is derived from using SHA-512. This is standard practice for Ed25519, where the
    other 32 bytes of the SHA-512 seed hash are used as a nonce during signing. If a new key pair has to be
    generated, this implementation generates a seed.
    """

    @property
    def model(self) -> IdentityKeyPairModel:
        """
        Returns:
            The internal state of this :class:`IdentityKeyPair` as a pydantic model.
        """

        return IdentityKeyPairModel(secret=self.secret, secret_type=self.secret_type)

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`IdentityKeyPair` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.json()))

    @staticmethod
    def from_model(model: IdentityKeyPairModel) -> "IdentityKeyPair":
        """
        Args:
            model: The pydantic model holding the internal state of an :class:`IdentityKeyPair`, as produced
                by :attr:`model`.

        Returns:
            A configured instance of :class:`IdentityKeyPair`, with internal state restored from the model.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        if model.secret_type is SecretType.PRIV:
            return IdentityKeyPairPriv(model.secret)
        if model.secret_type is SecretType.SEED:
            return IdentityKeyPairSeed(model.secret)

        return assert_never(model.secret_type)

    @staticmethod
    def from_json(serialized: JSONObject) -> "IdentityKeyPair":
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of an
                :class:`IdentityKeyPair`, as produced by :attr:`json`.

        Returns:
            A configured instance of :class:`IdentityKeyPair`, with internal state restored from the
            serialized data.
        """

        return IdentityKeyPair.from_model(parse_identity_key_pair_model(serialized))

    @property
    @abstractmethod
    def secret_type(self) -> SecretType:
        """
        Returns:
            The type of secret used by this identity key (i.e. a seed or private key).
        """

    @property
    @abstractmethod
    def secret(self) -> bytes:
        """
        Returns:
            The secret used by this identity key, i.e. the seed or private key.
        """

    @abstractmethod
    def as_priv(self) -> "IdentityKeyPairPriv":
        """
        Returns:
            An :class:`IdentityKeyPairPriv` derived from this instance, or the instance itself if it already
            is an :class:`IdentityKeyPairPriv`.
        """


class IdentityKeyPairPriv(IdentityKeyPair):
    """
    An :class:`IdentityKeyPair` represented by a Curve25519/Ed25519 private key.
    """

    def __init__(self, priv: bytes) -> None:
        """
        Args:
            priv: The Curve25519/Ed25519 private key.
        """

        if len(priv) != 32:
            raise ValueError("Expected the private key to be 32 bytes long.")

        self.__priv = priv

    @property
    def secret_type(self) -> SecretType:
        return SecretType.PRIV

    @property
    def secret(self) -> bytes:
        return self.priv

    def as_priv(self) -> "IdentityKeyPairPriv":
        return self

    @property
    def priv(self) -> bytes:
        """
        Returns:
            The Curve25519/Ed25519 private key.
        """

        return self.__priv


class IdentityKeyPairSeed(IdentityKeyPair):
    """
    An :class:`IdentityKeyPair` represented by a Curve25519/Ed25519 seed.
    """

    def __init__(self, seed: bytes) -> None:
        """
        Args:
            seed: The Curve25519/Ed25519 seed.
        """

        if len(seed) != 32:
            raise ValueError("Expected the seed to be 32 bytes long.")

        self.__seed = seed

    @property
    def secret_type(self) -> SecretType:
        return SecretType.SEED

    @property
    def secret(self) -> bytes:
        return self.seed

    def as_priv(self) -> "IdentityKeyPairPriv":
        return IdentityKeyPairPriv(xeddsa.seed_to_priv(self.__seed))

    @property
    def seed(self) -> bytes:
        """
        Returns:
            The Curve25519/Ed25519 seed.
        """

        return self.__seed
