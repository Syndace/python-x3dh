# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

import json
from typing import NamedTuple, cast

import xeddsa

from .migrations import parse_signed_pre_key_pair_model
from .models import SignedPreKeyPairModel
from .types import JSONObject


__all__ = [  # pylint: disable=unused-variable
    "SignedPreKeyPair"
]


class SignedPreKeyPair(NamedTuple):
    """
    A signed pre key, i.e. a pre key whose public key was encoded using an application-specific encoding
    format, then signed by the identity key, and stored together with a generation timestamp for periodic
    rotation.
    """

    priv: bytes
    sig: bytes
    timestamp: int

    @property
    def pub(self) -> bytes:
        """
        Returns:
            The public key of this signed pre key.
        """

        return xeddsa.priv_to_curve25519_pub(self.priv)

    @property
    def model(self) -> SignedPreKeyPairModel:
        """
        Returns:
            The internal state of this :class:`SignedPreKeyPair` as a pydantic model.
        """

        return SignedPreKeyPairModel(priv=self.priv, sig=self.sig, timestamp=self.timestamp)

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`SignedPreKeyPair` as a JSON-serializable Python object.
        """

        return cast(JSONObject, json.loads(self.model.json()))

    @staticmethod
    def from_model(model: SignedPreKeyPairModel) -> "SignedPreKeyPair":
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`SignedPreKeyPair`, as produced
                by :attr:`model`.

        Returns:
            A configured instance of :class:`SignedPreKeyPair`, with internal state restored from the model.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        return SignedPreKeyPair(priv=model.priv, sig=model.sig, timestamp=model.timestamp)

    @staticmethod
    def from_json(serialized: JSONObject) -> "SignedPreKeyPair":
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a
                :class:`SignedPreKeyPair`, as produced by :attr:`json`.

        Returns:
            A configured instance of :class:`SignedPreKeyPair`, with internal state restored from the
            serialized data.
        """

        return SignedPreKeyPair.from_model(parse_signed_pre_key_pair_model(serialized))
