# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from abc import abstractmethod
from typing import Optional, Tuple, Type, TypeVar

from .base_state import BaseState
from .crypto_provider import HashFunction
from .identity_key_pair import IdentityKeyPair
from .migrations import parse_base_state_model
from .models import BaseStateModel
from .signed_pre_key_pair import SignedPreKeyPair
from .types import Bundle, IdentityKeyFormat, Header, JSONObject


__all__ = [  # pylint: disable=unused-variable
    "State"
]


StateTypeT = TypeVar("StateTypeT", bound="State")


class State(BaseState):
    """
    This class is the core of this X3DH implementation. It manages the own :class:`~x3dh.types.Bundle` and
    offers methods to perform key agreements with other parties. Use :class:`~x3dh.base_state.BaseState`
    directly if manual state management is needed. Note that you can still use the methods available for
    manual state management, but doing so shouldn't be required.

    Warning:
        :meth:`rotate_signed_pre_key` should be called periodically to check whether the signed pre key needs
        to be rotated and to perform the rotation if necessary.
    """

    def __init__(self) -> None:
        super().__init__()

        # Just the type definitions here
        self.__signed_pre_key_rotation_period: int
        self.__pre_key_refill_threshold: int
        self.__pre_key_refill_target: int

    @classmethod
    def create(
        cls: Type[StateTypeT],
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        identity_key_pair: Optional[IdentityKeyPair] = None,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99,
        pre_key_refill_target: int = 100
    ) -> StateTypeT:
        """
        Args:
            identity_key_format: The format in which the identity public key is included in bundles/headers.
            hash_function: A 256 or 512-bit hash function.
            info: A (byte) string identifying the application.
            signed_pre_key_rotation_period: Rotate the signed pre key after this amount of time in seconds.
            pre_key_refill_threshold: Threshold for refilling the pre keys.
            pre_key_refill_target: When less then ``pre_key_refill_threshold`` pre keys are available,
                generate new ones until there are ``pre_key_refill_target`` pre keys again.
            identity_key_pair: If set, use the given identity key pair instead of generating a new one.

        Returns:
            A configured instance of :class:`~x3dh.state.State`.
        """
        # pylint: disable=protected-access

        if signed_pre_key_rotation_period < 1:
            raise ValueError(
                "Invalid value passed for the `signed_pre_key_rotation_period` parameter. The signed pre key"
                " rotation period must be at least one day."
            )

        if not 1 <= pre_key_refill_threshold <= pre_key_refill_target:
            raise ValueError(
                "Invalid value(s) passed for the `pre_key_refill_threshold` / `pre_key_refill_target`"
                " parameter(s). `pre_key_refill_threshold` must be greater than or equal to '1' and lower"
                " than or equal to `pre_key_refill_target`."
            )

        self = super().create(identity_key_format, hash_function, info, identity_key_pair)

        self.__signed_pre_key_rotation_period = signed_pre_key_rotation_period
        self.__pre_key_refill_threshold = pre_key_refill_threshold
        self.__pre_key_refill_target = pre_key_refill_target

        self.generate_pre_keys(pre_key_refill_target)

        # I believe this is a false positive by pylint
        self._publish_bundle(self.bundle)  # pylint: disable=no-member

        return self

    ####################
    # abstract methods #
    ####################

    @abstractmethod
    def _publish_bundle(self, bundle: Bundle) -> None:
        """
        Args:
            bundle: The bundle to publish, overwriting previously published data.

        Note:
            In addition to publishing the bundle, this method can be used as a trigger to persist the state.
            Persisting the state in this method guarantees always remaining up-to-date.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            Even though this method is expected to perform I/O, it is deliberately not marked as async, since
            completion of the I/O operation is not a requirement for the program flow to continue, and making
            this method async would complicate API design with regards to inheritance from
            :class:`~x3dh.base_state.BaseState`.
        """

        raise NotImplementedError("Create a subclass of State and implement `_publish_bundle`.")

    #################
    # serialization #
    #################

    @classmethod
    def from_model(
        cls: Type[StateTypeT],
        model: BaseStateModel,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99,
        pre_key_refill_target: int = 100
    ) -> StateTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`State`, as produced by
                :attr:`~x3dh.base_state.BaseState.model`.
            identity_key_format: The format in which the identity public key is included in bundles/headers.
            hash_function: A 256 or 512-bit hash function.
            info: A (byte) string identifying the application.
            signed_pre_key_rotation_period: Rotate the signed pre key after this amount of time in seconds.
            pre_key_refill_threshold: Threshold for refilling the pre keys.
            pre_key_refill_target: When less then ``pre_key_refill_threshold`` pre keys are available,
                generate new ones until there are ``pre_key_refill_target`` pre keys again.

        Returns:
            A configured instance of :class:`State`, with internal state restored from the model.

        Warning:
            Migrations are not provided via the :attr:`~x3dh.base_state.BaseState.model`/:meth:`from_model`
            API. Use :attr:`~x3dh.base_state.BaseState.json`/:meth:`from_json` instead. Refer to
            :ref:`serialization_and_migration` in the documentation for details.
        """
        # pylint: disable=protected-access

        if signed_pre_key_rotation_period < 1:
            raise ValueError(
                "Invalid value passed for the `signed_pre_key_rotation_period` parameter. The signed pre key"
                " rotation period must be at least one day."
            )

        if not 1 <= pre_key_refill_threshold <= pre_key_refill_target:
            raise ValueError(
                "Invalid value(s) passed for the `pre_key_refill_threshold` / `pre_key_refill_target`"
                " parameter(s). `pre_key_refill_threshold` must be greater than or equal to '1' and lower"
                " than or equal to `pre_key_refill_target`."
            )

        self = super().from_model(model, identity_key_format, hash_function, info)

        self.__signed_pre_key_rotation_period = signed_pre_key_rotation_period
        self.__pre_key_refill_threshold = pre_key_refill_threshold
        self.__pre_key_refill_target = pre_key_refill_target

        self.rotate_signed_pre_key()

        return self

    @classmethod
    def from_json(
        cls: Type[StateTypeT],
        serialized: JSONObject,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99,
        pre_key_refill_target: int = 100
    ) -> Tuple[StateTypeT, bool]:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a :class:`State`,
                as produced by :attr:`~x3dh.base_state.BaseState.json`.
            identity_key_format: The format in which the identity public key is included in bundles/headers.
            hash_function: A 256 or 512-bit hash function.
            info: A (byte) string identifying the application.
            signed_pre_key_rotation_period: Rotate the signed pre key after this amount of time in seconds.
            pre_key_refill_threshold: Threshold for refilling the pre keys.
            pre_key_refill_target: When less then ``pre_key_refill_threshold`` pre keys are available,
                generate new ones until there are ``pre_key_refill_target`` pre keys again.

        Returns:
            A configured instance of :class:`State`, with internal state restored from the serialized data,
            and a flag that indicates whether the bundle needed to be published. The latter was part of the
            pre-stable serialization format and is handled automatically by this :meth:`from_json`
            implementation.
        """
        # pylint: disable=protected-access

        model, bundle_needs_publish = parse_base_state_model(serialized)

        self = cls.from_model(
            model,
            identity_key_format,
            hash_function,
            info,
            signed_pre_key_rotation_period,
            pre_key_refill_threshold,
            pre_key_refill_target
        )

        if bundle_needs_publish:
            # I believe this is a false positive by pylint
            self._publish_bundle(self.bundle)  # pylint: disable=no-member

        return self, False

    #################################
    # key generation and management #
    #################################

    def rotate_signed_pre_key(self, force: bool = False) -> None:
        """
        Check whether the signed pre key is due for rotation, and rotate it if necessary. Call this method
        periodically to make sure the signed pre key is always up to date.

        Args:
            force: Whether to force rotation regardless of the age of the current signed pre key.
        """

        if force or self.signed_pre_key_age() > self.__signed_pre_key_rotation_period:
            super().rotate_signed_pre_key()

            self._publish_bundle(self.bundle)

    #################
    # key agreement #
    #################

    async def get_shared_secret_passive(
        self,
        header: Header,
        associated_data_appendix: bytes = b"",
        require_pre_key: bool = True
    ) -> Tuple[bytes, bytes, SignedPreKeyPair]:
        """
        Perform an X3DH key agreement, passively.

        Args:
            header: The header received from the active party.
            associated_data_appendix: Additional information to append to the associated data, like usernames,
                certificates or other identifying information.
            require_pre_key: Use this flag to abort the key agreement if the active party did not use a pre
                key.

        Returns:
            The shared secret and the associated data shared between both parties, and the signed pre key pair
            that was used during the key exchange, for use by follow-up protocols.

        Raises:
            KeyAgreementException: If an error occurs during the key agreement. The exception message will
                contain (human-readable) details.
        """

        shared_secret, associated_data, signed_pre_key_pair = await super().get_shared_secret_passive(
            header,
            associated_data_appendix,
            require_pre_key
        )

        # If a pre key was used, remove it from the pool and refill the pool if necessary
        if header.pre_key is not None:
            self.delete_pre_key(header.pre_key)

            if self.get_num_visible_pre_keys() < self.__pre_key_refill_threshold:
                self.generate_pre_keys(self.__pre_key_refill_target - self.get_num_visible_pre_keys())

            self._publish_bundle(self.bundle)

        return shared_secret, associated_data, signed_pre_key_pair
