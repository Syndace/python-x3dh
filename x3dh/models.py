from typing import Any, FrozenSet, Optional

from pydantic import BaseModel
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import PlainValidator
from typing_extensions import Annotated

from .types import SecretType


__all__ = [  # pylint: disable=unused-variable
    "BaseStateModel",
    "IdentityKeyPairModel",
    "SignedPreKeyPairModel"
]


def _json_bytes_decoder(val: Any) -> bytes:
    """
    Decode bytes from a string according to the JSON specification. See
    https://github.com/samuelcolvin/pydantic/issues/3756 for details.

    Args:
        val: The value to type check and decode.

    Returns:
        The value decoded to bytes. If the value is bytes already, it is returned unmodified.

    Raises:
        ValueError: if the value is not correctly encoded.
    """

    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes(map(ord, val))
    raise ValueError("bytes fields must be encoded as bytes or str.")


def _json_bytes_encoder(val: bytes) -> str:
    """
    Encode bytes as a string according to the JSON specification. See
    https://github.com/samuelcolvin/pydantic/issues/3756 for details.

    Args:
        val: The bytes to encode.

    Returns:
        The encoded bytes.
    """

    return "".join(map(chr, val))


JsonBytes = Annotated[bytes, PlainValidator(_json_bytes_decoder), PlainSerializer(_json_bytes_encoder)]


class IdentityKeyPairModel(BaseModel):
    """
    The model representing the internal state of an :class:`~x3dh.identity_key_pair.IdentityKeyPair`.
    """

    version: str = "1.0.0"
    secret: JsonBytes
    secret_type: SecretType


class SignedPreKeyPairModel(BaseModel):
    """
    The model representing the internal state of a :class:`~x3dh.signed_pre_key_pair.SignedPreKeyPair`.
    """

    version: str = "1.0.0"
    priv: JsonBytes
    sig: JsonBytes
    timestamp: int


class BaseStateModel(BaseModel):
    """
    The model representing the internal state of a :class:`~x3dh.base_state.BaseState`.
    """

    version: str = "1.0.0"
    identity_key: IdentityKeyPairModel
    signed_pre_key: SignedPreKeyPairModel
    old_signed_pre_key: Optional[SignedPreKeyPairModel]
    pre_keys: FrozenSet[JsonBytes]
