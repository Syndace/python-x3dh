from typing import Optional, Set

from pydantic import BaseModel

from .types import SecretType
from .version import __version__


# BASE64 UNTIL https://github.com/samuelcolvin/pydantic/issues/3756 IS FIXED


__all__ = [  # pylint: disable=unused-variable
    "BaseStateModel",
    "IdentityKeyPairModel",
    "SignedPreKeyPairModel"
]


class IdentityKeyPairModel(BaseModel):
    """
    The model representing the internal state of an :class:`~x3dh.identity_key_pair.IdentityKeyPair`.
    """

    version: str = __version__["short"]
    secret_b64: bytes
    secret_type: SecretType


class SignedPreKeyPairModel(BaseModel):
    """
    The model representing the internal state of a :class:`~x3dh.signed_pre_key_pair.SignedPreKeyPair`.
    """

    version: str = __version__["short"]
    priv_b64: bytes
    sig_b64: bytes
    timestamp: int


class BaseStateModel(BaseModel):
    """
    The model representing the internal state of a :class:`~x3dh.base_state.BaseState`.
    """

    version: str = __version__["short"]
    identity_key: IdentityKeyPairModel
    signed_pre_key: SignedPreKeyPairModel
    old_signed_pre_key: Optional[SignedPreKeyPairModel]
    pre_keys_b64: Set[bytes]
