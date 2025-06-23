from __future__ import annotations

import base64
from typing import List, Tuple, cast

from pydantic import BaseModel

from .models import IdentityKeyPairModel, SignedPreKeyPairModel, BaseStateModel
from .types import JSONObject, SecretType


__all__ = [
    "parse_identity_key_pair_model",
    "parse_signed_pre_key_pair_model",
    "parse_base_state_model"
]


class PreStableKeyPairModel(BaseModel):
    """
    This model describes how a key pair was serialized in pre-stable serialization format.
    """

    priv: str
    pub: str


class PreStableSignedPreKeyModel(BaseModel):
    """
    This model describes how a signed pre-key was serialized in pre-stable serialization format.
    """

    key: PreStableKeyPairModel
    signature: str
    timestamp: float


class PreStableModel(BaseModel):
    """
    This model describes how State instances were serialized in pre-stable serialization format.
    """

    changed: bool
    ik: PreStableKeyPairModel
    spk: PreStableSignedPreKeyModel
    otpks: List[PreStableKeyPairModel]


def parse_identity_key_pair_model(serialized: JSONObject) -> IdentityKeyPairModel:
    """
    Parse a serialized :class:`~x3dh.identity_key_pair.IdentityKeyPair` instance, as returned by
    :attr:`~x3dh.identity_key_pair.IdentityKeyPair.json`, into the most recent pydantic model available for
    the class. Perform migrations in case the pydantic models were updated.

    Args:
        serialized: The serialized instance.

    Returns:
        The model, which can be used to restore the instance using
        :meth:`~x3dh.identity_key_pair.IdentityKeyPair.from_model`.

    Note:
        Pre-stable data can only be migrated as a whole using :func:`parse_base_state_model`.
    """

    # Each model has a Python string "version" in its root. Use that to find the model that the data was
    # serialized from.
    version = cast(str, serialized["version"])
    model: BaseModel = {
        "1.0.0": IdentityKeyPairModel,
        "1.0.1": IdentityKeyPairModel
    }[version](**serialized)  # type: ignore[arg-type]

    # Once all migrations have been applied, the model should be an instance of the most recent model
    assert isinstance(model, IdentityKeyPairModel)

    return model


def parse_signed_pre_key_pair_model(serialized: JSONObject) -> SignedPreKeyPairModel:
    """
    Parse a serialized :class:`~x3dh.signed_pre_key_pair.SignedPreKeyPair` instance, as returned by
    :attr:`~x3dh.signed_pre_key_pair.SignedPreKeyPair.json`, into the most recent pydantic model available for
    the class. Perform migrations in case the pydantic models were updated.

    Args:
        serialized: The serialized instance.

    Returns:
        The model, which can be used to restore the instance using
        :meth:`~x3dh.signed_pre_key_pair.SignedPreKeyPair.from_model`.

    Note:
        Pre-stable data can only be migrated as a whole using :func:`parse_base_state_model`.
    """

    # Each model has a Python string "version" in its root. Use that to find the model that the data was
    # serialized from.
    version = cast(str, serialized["version"])
    model: BaseModel = {
        "1.0.0": SignedPreKeyPairModel,
        "1.0.1": SignedPreKeyPairModel
    }[version](**serialized)  # type: ignore[arg-type]

    # Once all migrations have been applied, the model should be an instance of the most recent model
    assert isinstance(model, SignedPreKeyPairModel)

    return model


def parse_base_state_model(serialized: JSONObject) -> Tuple[BaseStateModel, bool]:
    """
    Parse a serialized :class:`~x3dh.base_state.BaseState` instance, as returned by
    :attr:`~x3dh.base_state.BaseState.json`, into the most recent pydantic model available for the class.
    Perform migrations in case the pydantic models were updated. Supports migration of pre-stable data.

    Args:
        serialized: The serialized instance.

    Returns:
        The model, which can be used to restore the instance using
        :meth:`~x3dh.base_state.BaseState.from_model`, and a flag that indicates whether the bundle needs to
        be published, which was part of the pre-stable serialization format.
    """

    bundle_needs_publish = False

    # Each model has a Python string "version" in its root. Use that to find the model that the data was
    # serialized from. Special case: the pre-stable serialization format does not contain a version.
    version = cast(str, serialized["version"]) if "version" in serialized else None
    model: BaseModel = {
        None: PreStableModel,
        "1.0.0": BaseStateModel,
        "1.0.1": BaseStateModel
    }[version](**serialized)

    if isinstance(model, PreStableModel):
        # Run migrations from PreStableModel to StateModel
        bundle_needs_publish = bundle_needs_publish or model.changed

        model = BaseStateModel(
            identity_key=IdentityKeyPairModel(
                secret=base64.b64decode(model.ik.priv),
                secret_type=SecretType.PRIV
            ),
            signed_pre_key=SignedPreKeyPairModel(
                priv=base64.b64decode(model.spk.key.priv),
                sig=base64.b64decode(model.spk.signature),
                timestamp=int(model.spk.timestamp)
            ),
            old_signed_pre_key=None,
            pre_keys=frozenset({ base64.b64decode(pre_key.priv) for pre_key in model.otpks })
        )

    # Once all migrations have been applied, the model should be an instance of the most recent model
    assert isinstance(model, BaseStateModel)

    return model, bundle_needs_publish
